package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/signrpc"
	"github.com/lightningnetwork/lnd/macaroons"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"gopkg.in/macaroon.v2"
)

// htlcsuccess crafts and signs a single-input transaction that spends a
// remote-offered HTLC output with a known preimage. It uses the existing
// Signer RPC to obtain the signature and prints the raw transaction hex
// without broadcasting it.
//
// Required flags:
//
//	-outpoint
//	-output_value_sat
//	-htlc_pk_script
//	-witness_script
//	-preimage
//
// Provide either -sweep_pk_script or -sweep_addr for the destination. Set
// -taproot and supply -control_block for taproot HTLC outputs.
// The HTLC key locator is given via -key_family and -key_index, with an
// optional -single_tweak for legacy commitments.
// Fee rate is controlled with -sat_per_vbyte.
const (
	defaultRPCHost      = "localhost:10009"
	defaultTLSCert      = "/Library/Application Support/Lnd/tls.cert"
	defaultMacaroonPath = "/Library/Application Support/Lnd/data/chain/bitcoin/mainnet/admin.macaroon"
)

// flagSlice allows repeatable string flags.
type flagSlice []string

func (s *flagSlice) String() string {
	return strings.Join(*s, ",")
}

func (s *flagSlice) Set(v string) error {
	*s = append(*s, v)
	return nil
}

type additionalInput struct {
	txIn  *wire.TxIn
	value int64
}

func main() {
	var (
		rpcServer = flag.String("rpcserver", defaultRPCHost, "lnd gRPC host:port")
		tlsPath   = flag.String("tlscert", "", "path to lnd tls.cert")
		macPath   = flag.String("macaroon", "", "path to admin macaroon")

		outpointStr      = flag.String("outpoint", "", "HTLC outpoint <txid>:<index>")
		outputValueSat   = flag.Int64("output_value_sat", 0, "value of the HTLC output in satoshis")
		htlcPkScriptHex  = flag.String("htlc_pk_script", "", "hex-encoded pk_script of the HTLC output")
		witnessScriptHex = flag.String("witness_script", "", "hex-encoded witness script for the success path")
		controlBlockHex  = flag.String("control_block", "", "hex-encoded taproot control block (taproot only)")
		preimageHex      = flag.String("preimage", "", "32-byte payment preimage in hex")

		sweepAddr        = flag.String("sweep_addr", "", "address to sweep funds to")
		sweepPkScriptHex = flag.String("sweep_pk_script", "", "hex-encoded sweep pk_script (overrides sweep_addr)")

		keyFamily = flag.Int("key_family", 0, "key family for the HTLC key")
		keyIndex  = flag.Int("key_index", 0, "key index for the HTLC key")

		singleTweakHex = flag.String("single_tweak", "", "optional single tweak hex for legacy HTLC keys")
		satPerVByte    = flag.Float64("sat_per_vbyte", 1.0, "fee rate in sat/vbyte")
		taproot        = flag.Bool("taproot", false, "set if the HTLC output is taproot")

		feeOverrideSat = flag.Int64("fee_override_sat", 0, "manual fee in satoshis (required if adding extra inputs)")

		extraInputs  flagSlice
		extraOutputs flagSlice
		opReturns    flagSlice
	)

	flag.Var(&extraInputs, "add_input", "extra input as txid:vout[:sequence] or txid:vout:value[:sequence] (unsigned)")
	flag.Var(&extraOutputs, "add_output", "extra output as value_sats:pk_script_hex")
	flag.Var(&opReturns, "add_op_return", "OP_RETURN data hex (value 0)")

	flag.Parse()

	if err := run(
		*rpcServer, *tlsPath, *macPath, *outpointStr, *outputValueSat,
		*htlcPkScriptHex, *witnessScriptHex, *controlBlockHex,
		*preimageHex, *sweepAddr, *sweepPkScriptHex, *keyFamily,
		*keyIndex, *singleTweakHex, *satPerVByte, *taproot,
		*feeOverrideSat, extraInputs, extraOutputs, opReturns,
	); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(rpcServer, tlsPath, macPath, outpointStr string, outputValueSat int64,
	htlcPkScriptHex, witnessScriptHex, controlBlockHex, preimageHex,
	sweepAddr, sweepPkScriptHex string, keyFamily, keyIndex int,
	singleTweakHex string, satPerVByte float64, taproot bool,
	feeOverrideSat int64, extraInputs, extraOutputs, opReturns flagSlice) error {

	if outpointStr == "" || outputValueSat <= 0 || htlcPkScriptHex == "" ||
		witnessScriptHex == "" || preimageHex == "" {

		return fmt.Errorf("outpoint, output_value_sat, htlc_pk_script, " +
			"witness_script and preimage are required")
	}

	outpoint, err := parseOutPoint(outpointStr)
	if err != nil {
		return err
	}

	htlcPkScript, err := hex.DecodeString(htlcPkScriptHex)
	if err != nil {
		return fmt.Errorf("invalid htlc_pk_script: %w", err)
	}

	witnessScript, err := hex.DecodeString(witnessScriptHex)
	if err != nil {
		return fmt.Errorf("invalid witness_script: %w", err)
	}

	preimage, err := hex.DecodeString(preimageHex)
	if err != nil {
		return fmt.Errorf("invalid preimage: %w", err)
	}
	if len(preimage) != 32 {
		return fmt.Errorf("preimage must be 32 bytes")
	}

	var controlBlock []byte
	if taproot {
		if controlBlockHex == "" {
			return fmt.Errorf("control_block required for taproot spend")
		}
		controlBlock, err = hex.DecodeString(controlBlockHex)
		if err != nil {
			return fmt.Errorf("invalid control_block: %w", err)
		}
	}

	singleTweak, err := parseOptionalHex(singleTweakHex)
	if err != nil {
		return fmt.Errorf("invalid single_tweak: %w", err)
	}

	if satPerVByte <= 0 {
		return fmt.Errorf("sat_per_vbyte must be > 0")
	}

	if tlsPath == "" || macPath == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("unable to detect home dir: %w", err)
		}
		base := filepath.Join(homeDir, "")
		if tlsPath == "" {
			tlsPath = filepath.Join(base, defaultTLSCert)
		}
		if macPath == "" {
			macPath = filepath.Join(base, defaultMacaroonPath)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := dialLnd(ctx, rpcServer, tlsPath, macPath)
	if err != nil {
		return err
	}
	defer conn.Close()

	sweepPkScript, err := resolveSweepPkScript(
		ctx, conn, sweepPkScriptHex, sweepAddr,
	)
	if err != nil {
		return err
	}

	addInputs := make([]additionalInput, 0, len(extraInputs))
	for i, inStr := range extraInputs {
		input, err := parseExtraInput(inStr)
		if err != nil {
			return fmt.Errorf("add_input %d: %w", i, err)
		}
		addInputs = append(addInputs, input)
	}

	addOutputs := make([]*wire.TxOut, 0, len(extraOutputs))
	var addOutputValue int64
	for i, outStr := range extraOutputs {
		txOut, err := parseExtraOutput(outStr)
		if err != nil {
			return fmt.Errorf("add_output %d: %w", i, err)
		}
		addOutputValue += txOut.Value
		addOutputs = append(addOutputs, txOut)
	}

	opReturnOutputs := make([]*wire.TxOut, 0, len(opReturns))
	for i, dataHex := range opReturns {
		txOut, err := buildOpReturnOutput(dataHex)
		if err != nil {
			return fmt.Errorf("add_op_return %d: %w", i, err)
		}
		opReturnOutputs = append(opReturnOutputs, txOut)
	}

	totalInputValue := outputValueSat
	for _, in := range addInputs {
		totalInputValue += in.value
	}

	witnessType := input.HtlcAcceptedRemoteSuccess
	if taproot {
		witnessType = input.TaprootHtlcAcceptedRemoteSuccess
	}

	var fee int64
	switch {
	case feeOverrideSat > 0:
		fee = feeOverrideSat
	case len(addInputs) > 0:
		return fmt.Errorf("fee_override_sat must be set when adding extra inputs")
	default:
		fee, err = estimateFee(
			sweepPkScript, witnessType, addOutputs, opReturnOutputs,
			satPerVByte,
		)
		if err != nil {
			return err
		}
	}

	for _, txOut := range opReturnOutputs {
		addOutputValue += txOut.Value
	}

	sweepValue := totalInputValue - addOutputValue - fee
	if sweepValue <= 0 {
		return fmt.Errorf("sweep value would be non-positive after " +
			"fee; try lowering fee rate or confirm HTLC amount")
	}

	sweepTx := wire.NewMsgTx(2)
	sweepTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: *outpoint,
		// Use non-final sequence to satisfy CSV=1 outputs (anchors).
		Sequence: 1,
	})
	for _, in := range addInputs {
		sweepTx.AddTxIn(in.txIn)
	}
	sweepTx.AddTxOut(&wire.TxOut{
		Value:    sweepValue,
		PkScript: sweepPkScript,
	})
	for _, txOut := range addOutputs {
		sweepTx.AddTxOut(txOut)
	}
	for _, txOut := range opReturnOutputs {
		sweepTx.AddTxOut(txOut)
	}

	sighash := txscript.SigHashAll
	signMethod := signrpc.SignMethod_SIGN_METHOD_WITNESS_V0
	if taproot {
		sighash = txscript.SigHashDefault
		signMethod = signrpc.SignMethod_SIGN_METHOD_TAPROOT_SCRIPT_SPEND
	}

	signReq, err := buildSignReq(
		sweepTx, htlcPkScript, outputValueSat, witnessScript,
		singleTweak, keyFamily, keyIndex, sighash, signMethod, taproot,
	)
	if err != nil {
		return err
	}

	signer := signrpc.NewSignerClient(conn)
	signResp, err := signer.SignOutputRaw(ctx, signReq)
	if err != nil {
		return fmt.Errorf("signing failed: %w", err)
	}

	if len(signResp.RawSigs) != 1 {
		return fmt.Errorf("unexpected signature response")
	}
	sig := signResp.RawSigs[0]

	witness, err := buildWitness(
		sig, sighash, preimage, witnessScript, controlBlock, taproot,
	)
	if err != nil {
		return err
	}
	sweepTx.TxIn[0].Witness = witness

	var buf bytes.Buffer
	if err := sweepTx.Serialize(&buf); err != nil {
		return fmt.Errorf("serialize tx: %w", err)
	}

	rawHex := hex.EncodeToString(buf.Bytes())

	fmt.Printf("Sweep value: %d sat\n", sweepValue)
	if feeOverrideSat > 0 {
		fmt.Printf("Fee: %d sat (manual override)\n", fee)
	} else {
		fmt.Printf("Fee: %d sat (rate %.3f sat/vbyte)\n", fee, satPerVByte)
	}
	fmt.Printf("Raw transaction: %s\n", rawHex)

	return nil
}

func dialLnd(ctx context.Context, rpcServer, tlsPath, macPath string) (*grpc.ClientConn, error) {
	creds, err := credentials.NewClientTLSFromFile(tlsPath, "")
	if err != nil {
		return nil, fmt.Errorf("load TLS cert: %w", err)
	}

	macBytes, err := os.ReadFile(macPath)
	if err != nil {
		return nil, fmt.Errorf("read macaroon: %w", err)
	}

	mac := &macaroon.Macaroon{}
	if err := mac.UnmarshalBinary(macBytes); err != nil {
		return nil, fmt.Errorf("decode macaroon: %w", err)
	}

	macCred, err := macaroons.NewMacaroonCredential(mac)
	if err != nil {
		return nil, fmt.Errorf("macaroon credential: %w", err)
	}

	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		grpc.WithPerRPCCredentials(macCred),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(50<<20),
			grpc.MaxCallSendMsgSize(50<<20),
		),
	}

	conn, err := grpc.DialContext(ctx, rpcServer, opts...)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", rpcServer, err)
	}

	return conn, nil
}

func parseOutPoint(s string) (*wire.OutPoint, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return nil, fmt.Errorf("outpoint must be <txid>:<index>")
	}

	hash, err := chainhash.NewHashFromStr(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid txid: %w", err)
	}

	var index uint32
	_, err = fmt.Sscanf(parts[1], "%d", &index)
	if err != nil {
		return nil, fmt.Errorf("invalid index: %w", err)
	}

	return &wire.OutPoint{
		Hash:  *hash,
		Index: index,
	}, nil
}

func parseOptionalHex(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}

	return hex.DecodeString(s)
}

func parseExtraInput(s string) (additionalInput, error) {
	parts := strings.Split(s, ":")
	if len(parts) < 2 || len(parts) > 4 {
		return additionalInput{}, fmt.Errorf("add_input must be txid:vout[:sequence] or txid:vout:value:sequence")
	}

	hash, err := chainhash.NewHashFromStr(parts[0])
	if err != nil {
		return additionalInput{}, fmt.Errorf("invalid txid: %w", err)
	}

	vout, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return additionalInput{}, fmt.Errorf("invalid vout: %w", err)
	}

	sequence := uint32(wire.MaxTxInSequenceNum)
	value := int64(0)

	switch len(parts) {
	case 3:
		seq, err := strconv.ParseUint(parts[2], 10, 32)
		if err != nil {
			return additionalInput{}, fmt.Errorf("invalid sequence: %w", err)
		}
		sequence = uint32(seq)
	case 4:
		val, err := strconv.ParseInt(parts[2], 10, 64)
		if err != nil {
			return additionalInput{}, fmt.Errorf("invalid value: %w", err)
		}
		if val < 0 {
			return additionalInput{}, fmt.Errorf("value must be >= 0")
		}
		value = val

		seq, err := strconv.ParseUint(parts[3], 10, 32)
		if err != nil {
			return additionalInput{}, fmt.Errorf("invalid sequence: %w", err)
		}
		sequence = uint32(seq)
	}

	return additionalInput{
		txIn: &wire.TxIn{
			PreviousOutPoint: wire.OutPoint{
				Hash:  *hash,
				Index: uint32(vout),
			},
			Sequence: sequence,
		},
		value: value,
	}, nil
}

func parseExtraOutput(s string) (*wire.TxOut, error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("add_output must be value_sats:pk_script_hex")
	}

	value, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid output value: %w", err)
	}
	if value <= 0 {
		return nil, fmt.Errorf("output value must be > 0")
	}

	pkScript, err := hex.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid output pk_script: %w", err)
	}

	return &wire.TxOut{
		Value:    value,
		PkScript: pkScript,
	}, nil
}

func buildOpReturnOutput(dataHex string) (*wire.TxOut, error) {
	data, err := hex.DecodeString(dataHex)
	if err != nil {
		return nil, fmt.Errorf("invalid OP_RETURN data: %w", err)
	}

	script, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_RETURN).
		AddData(data).
		Script()
	if err != nil {
		return nil, fmt.Errorf("build OP_RETURN script: %w", err)
	}

	return &wire.TxOut{
		Value:    0,
		PkScript: script,
	}, nil
}

func estimateFee(sweepPkScript []byte, witnessType input.WitnessType,
	extraOutputs, opReturnOutputs []*wire.TxOut,
	satPerVByte float64) (int64, error) {

	var estimator input.TxWeightEstimator
	if err := witnessType.AddWeightEstimation(&estimator); err != nil {
		return 0, err
	}
	estimator.AddOutput(sweepPkScript)
	for _, txOut := range extraOutputs {
		estimator.AddOutput(txOut.PkScript)
	}
	for _, txOut := range opReturnOutputs {
		estimator.AddOutput(txOut.PkScript)
	}

	weight := float64(estimator.Weight())
	vsize := weight / blockchain.WitnessScaleFactor
	fee := math.Ceil(vsize * satPerVByte)

	return int64(fee), nil
}

func resolveSweepPkScript(ctx context.Context, conn *grpc.ClientConn,
	sweepPkScriptHex, sweepAddr string) ([]byte, error) {

	if sweepPkScriptHex != "" {
		return hex.DecodeString(sweepPkScriptHex)
	}

	if sweepAddr == "" {
		return nil, fmt.Errorf("either sweep_pk_script or sweep_addr " +
			"must be provided")
	}

	network, err := detectNetwork(ctx, conn)
	if err != nil {
		return nil, err
	}

	addr, err := btcutil.DecodeAddress(sweepAddr, network)
	if err != nil {
		return nil, fmt.Errorf("decode sweep_addr: %w", err)
	}

	return txscript.PayToAddrScript(addr)
}

func detectNetwork(ctx context.Context, conn *grpc.ClientConn) (*chaincfg.Params, error) {
	lnClient := lnrpc.NewLightningClient(conn)
	info, err := lnClient.GetInfo(ctx, &lnrpc.GetInfoRequest{})
	if err != nil {
		return nil, fmt.Errorf("GetInfo failed: %w", err)
	}

	if len(info.Chains) == 0 {
		return nil, fmt.Errorf("node reported no chains")
	}

	switch strings.ToLower(info.Chains[0].Network) {
	case "mainnet":
		return &chaincfg.MainNetParams, nil
	case "testnet", "testnet3":
		return &chaincfg.TestNet3Params, nil
	case "simnet":
		return &chaincfg.SimNetParams, nil
	case "regtest":
		return &chaincfg.RegressionNetParams, nil
	default:
		return nil, fmt.Errorf("unknown network %s", info.Chains[0].Network)
	}
}

func buildSignReq(tx *wire.MsgTx, htlcPkScript []byte, outputValueSat int64,
	witnessScript, singleTweak []byte, keyFamily, keyIndex int,
	sighash txscript.SigHashType, signMethod signrpc.SignMethod,
	taproot bool) (*signrpc.SignReq, error) {

	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		return nil, fmt.Errorf("serialize tx for signing: %w", err)
	}

	signDesc := &signrpc.SignDescriptor{
		KeyDesc: &signrpc.KeyDescriptor{
			KeyLoc: &signrpc.KeyLocator{
				KeyFamily: int32(keyFamily),
				KeyIndex:  int32(keyIndex),
			},
		},
		SingleTweak:   singleTweak,
		WitnessScript: witnessScript,
		Output: &signrpc.TxOut{
			Value:    outputValueSat,
			PkScript: htlcPkScript,
		},
		Sighash:    uint32(sighash),
		InputIndex: 0,
		SignMethod: signMethod,
	}

	signReq := &signrpc.SignReq{
		RawTxBytes: buf.Bytes(),
		SignDescs:  []*signrpc.SignDescriptor{signDesc},
	}

	if taproot {
		signReq.PrevOutputs = []*signrpc.TxOut{
			{
				Value:    outputValueSat,
				PkScript: htlcPkScript,
			},
		}
	}

	return signReq, nil
}

func buildWitness(sig []byte, sighash txscript.SigHashType, preimage,
	witnessScript, controlBlock []byte, taproot bool) (wire.TxWitness, error) {

	if taproot {
		if len(controlBlock) == 0 {
			return nil, fmt.Errorf("control_block required for taproot")
		}

		sigBytes := append([]byte{}, sig...)
		if sighash != txscript.SigHashDefault {
			sigBytes = append(sigBytes, byte(sighash))
		}

		return wire.TxWitness{
			sigBytes,
			preimage,
			witnessScript,
			controlBlock,
		}, nil
	}

	sigBytes := append([]byte{}, sig...)
	sigBytes = append(sigBytes, byte(sighash))

	return wire.TxWitness{
		sigBytes,
		preimage,
		witnessScript,
	}, nil
}
