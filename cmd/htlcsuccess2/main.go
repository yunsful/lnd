package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/lnrpc/signrpc"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/lightningnetwork/lnd/macaroons"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"gopkg.in/macaroon.v2"
)

// htlcsuccess2 crafts and signs a second-level HTLC success transaction for
// outputs on the local commitment. The HTLC input (index 0) is signed via the
// Signer RPC and combined with the sender signature. Optional extra inputs and
// outputs are allowed only when sighash is SINGLE|ANYONECANPAY (anchor HTLCs).
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
	txIn     *wire.TxIn
	value    int64
	pkScript []byte
}

type taprootSigInput struct {
	index        int
	privKey      *btcec.PrivateKey
	pkScript     []byte
	tapscript    []byte
	controlBlock []byte
	sighash      txscript.SigHashType
}

func main() {
	var (
		rpcServer = flag.String("rpcserver", defaultRPCHost, "lnd gRPC host:port")
		tlsPath   = flag.String("tlscert", "", "path to lnd tls.cert")
		macPath   = flag.String("macaroon", "", "path to admin macaroon")
		network   = flag.String("network", "mainnet", "network for address decoding")

		outpointStr      = flag.String("outpoint", "", "HTLC outpoint <txid>:<index>")
		outputValueSat   = flag.Int64("output_value_sat", 0, "value of the HTLC output in satoshis")
		htlcPkScriptHex  = flag.String("htlc_pk_script", "", "hex-encoded pk_script of the HTLC output")
		witnessScriptHex = flag.String("witness_script", "", "hex-encoded witness script for the HTLC success path")
		controlBlockHex  = flag.String("control_block", "", "hex-encoded taproot control block (taproot only)")
		preimageHex      = flag.String("preimage", "", "32-byte payment preimage in hex")

		senderSigHex     = flag.String("sender_sig", "", "hex-encoded sender signature (DER or schnorr)")
		sighashStr       = flag.String("sighash", "all", "sighash for local sig: all|single_anyonecanpay|default|0x..")
		senderSighashStr = flag.String("sender_sighash", "", "optional sighash for sender sig (defaults to sighash)")
		htlcSequence     = flag.Int("htlc_sequence", -1, "sequence for HTLC input (default auto)")

		secondLevelPkHex    = flag.String("second_level_pk_script", "", "hex-encoded pk_script for the second-level output")
		secondLevelValueSat = flag.Int64("second_level_value_sat", 0, "value of the second-level output in satoshis")

		keyFamily = flag.Int("key_family", 0, "key family for the HTLC key")
		keyIndex  = flag.Int("key_index", 0, "key index for the HTLC key")

		singleTweakHex = flag.String("single_tweak", "", "optional single tweak hex for legacy HTLC keys")
		taproot        = flag.Bool("taproot", false, "set if the HTLC output is taproot")

		inputsJSON  = flag.String("add_inputs_json", "", "extra inputs JSON (createrawtransaction format)")
		outputsJSON = flag.String("add_outputs_json", "", "extra outputs JSON (createrawtransaction format)")

		extraInputs  flagSlice
		extraOutputs flagSlice
		inputWitness flagSlice
		taprootSig   flagSlice
		opReturns    flagSlice
	)

	flag.Var(&extraInputs, "add_input", "extra input as txid:vout[:sequence] or txid:vout:value:sequence")
	flag.Var(&extraOutputs, "add_output", "extra output as value_sats:pk_script_hex")
	flag.Var(&inputWitness, "add_input_witness", "extra input witness as index:hex,hex,... (stack items)")
	flag.Var(&taprootSig, "add_input_taproot_sig", "auto-sign taproot input as index:privkey:pk_script:tapscript:control_block[:sighash]")
	flag.Var(&opReturns, "add_op_return", "OP_RETURN data hex (value 0)")

	flag.Parse()

	if err := run(
		*rpcServer, *tlsPath, *macPath, *network, *outpointStr, *outputValueSat,
		*htlcPkScriptHex, *witnessScriptHex, *controlBlockHex,
		*preimageHex, *senderSigHex, *sighashStr, *senderSighashStr,
		*htlcSequence, *secondLevelPkHex, *secondLevelValueSat, *keyFamily,
		*keyIndex, *singleTweakHex, *taproot, *inputsJSON, *outputsJSON,
		extraInputs, extraOutputs, inputWitness, taprootSig, opReturns,
	); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(rpcServer, tlsPath, macPath, network, outpointStr string, outputValueSat int64,
	htlcPkScriptHex, witnessScriptHex, controlBlockHex, preimageHex,
	senderSigHex, sighashStr, senderSighashStr string, htlcSequence int,
	secondLevelPkHex string, secondLevelValueSat int64, keyFamily, keyIndex int,
	singleTweakHex string, taproot bool, inputsJSON, outputsJSON string,
	extraInputs, extraOutputs, inputWitness, taprootSig, opReturns flagSlice) error {

	if outpointStr == "" || outputValueSat <= 0 || htlcPkScriptHex == "" ||
		witnessScriptHex == "" || preimageHex == "" || senderSigHex == "" ||
		secondLevelPkHex == "" || secondLevelValueSat <= 0 {

		return fmt.Errorf("outpoint, output_value_sat, htlc_pk_script, " +
			"witness_script, preimage, sender_sig, second_level_pk_script " +
			"and second_level_value_sat are required")
	}

	sighash, err := parseSigHash(sighashStr, taproot)
	if err != nil {
		return fmt.Errorf("invalid sighash: %w", err)
	}
	senderSigHash := sighash
	if senderSighashStr != "" {
		senderSigHash, err = parseSigHash(senderSighashStr, taproot)
		if err != nil {
			return fmt.Errorf("invalid sender_sighash: %w", err)
		}
	}

	params, err := networkParams(network)
	if err != nil {
		return err
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

	senderSig, err := hex.DecodeString(senderSigHex)
	if err != nil {
		return fmt.Errorf("invalid sender_sig: %w", err)
	}

	secondLevelPkScript, err := hex.DecodeString(secondLevelPkHex)
	if err != nil {
		return fmt.Errorf("invalid second_level_pk_script: %w", err)
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
	} else {
		if sighash == txscript.SigHashDefault ||
			senderSigHash == txscript.SigHashDefault {
			return fmt.Errorf("sighash default is only valid for taproot")
		}
	}

	singleTweak, err := parseOptionalHex(singleTweakHex)
	if err != nil {
		return fmt.Errorf("invalid single_tweak: %w", err)
	}

	addInputs := make([]additionalInput, 0, len(extraInputs))
	needsWalletLookup := false
	for i, inStr := range extraInputs {
		input, err := parseExtraInput(inStr)
		if err != nil {
			return fmt.Errorf("add_input %d: %w", i, err)
		}
		if input.value <= 0 {
			needsWalletLookup = true
		}
		addInputs = append(addInputs, input)
	}

	addOutputs := make([]*wire.TxOut, 0, len(extraOutputs))
	for i, outStr := range extraOutputs {
		txOut, err := parseExtraOutput(outStr)
		if err != nil {
			return fmt.Errorf("add_output %d: %w", i, err)
		}
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

	jsonInputs, err := parseInputsJSON(inputsJSON)
	if err != nil {
		return err
	}
	if len(jsonInputs) > 0 {
		needsWalletLookup = true
	}
	fmt.Printf("Extra inputs (json): %d\n", len(jsonInputs))
	fmt.Printf("Extra inputs (flags): %d\n", len(extraInputs))
	for i, in := range jsonInputs {
		seq := uint32(wire.MaxTxInSequenceNum)
		if in.Sequence != nil {
			seq = *in.Sequence
		}
		addInputs = append(addInputs, additionalInput{
			txIn: &wire.TxIn{
				PreviousOutPoint: wire.OutPoint{
					Hash:  in.Hash,
					Index: in.Vout,
				},
				Sequence: seq,
			},
			value: 0,
		})
		if in.Sequence != nil && *in.Sequence > wire.MaxTxInSequenceNum {
			return fmt.Errorf("inputs_json %d: sequence out of range", i)
		}
	}

	jsonOutputs, jsonOpReturns, err := parseOutputsJSON(outputsJSON, params)
	if err != nil {
		return err
	}
	addOutputs = append(addOutputs, jsonOutputs...)
	opReturnOutputs = append(opReturnOutputs, jsonOpReturns...)
	fmt.Printf("Extra outputs (json): %d\n", len(jsonOutputs))
	fmt.Printf("Extra outputs (flags): %d\n", len(extraOutputs))
	fmt.Printf("OP_RETURN outputs (json): %d\n", len(jsonOpReturns))
	fmt.Printf("OP_RETURN outputs (flags): %d\n", len(opReturns))
	fmt.Printf("Needs wallet lookup: %t\n", needsWalletLookup)

	taprootSigInputs := make([]taprootSigInput, 0, len(taprootSig))
	for i, sigStr := range taprootSig {
		entry, err := parseTaprootSigInput(sigStr)
		if err != nil {
			return fmt.Errorf("add_input_taproot_sig %d: %w", i, err)
		}
		taprootSigInputs = append(taprootSigInputs, entry)
	}

	anchorSigHash := txscript.SigHashSingle | txscript.SigHashAnyOneCanPay
	if (len(addInputs) > 0 || len(addOutputs) > 0 || len(opReturnOutputs) > 0) &&
		(sighash != anchorSigHash || senderSigHash != anchorSigHash) {
		return fmt.Errorf("extra inputs/outputs require sighash single|anyonecanpay")
	}

	seq := uint32(0)
	if htlcSequence >= 0 {
		seq = uint32(htlcSequence)
	} else if sighash == anchorSigHash {
		seq = 1
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

	if needsWalletLookup {
		utxos, err := fetchWalletUtxos(ctx, conn)
		if err != nil {
			return err
		}
		for i := range addInputs {
			if addInputs[i].value > 0 {
				continue
			}
			key := outpointKey(
				addInputs[i].txIn.PreviousOutPoint.Hash,
				addInputs[i].txIn.PreviousOutPoint.Index,
			)
			utxo, ok := utxos[key]
			if !ok {
				return fmt.Errorf("wallet utxo not found for input %s", key)
			}
			addInputs[i].value = utxo.value
			addInputs[i].pkScript = utxo.pkScript
		}
	}

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: *outpoint,
		Sequence:         seq,
	})
	for _, in := range addInputs {
		tx.AddTxIn(in.txIn)
	}
	tx.AddTxOut(&wire.TxOut{
		Value:    secondLevelValueSat,
		PkScript: secondLevelPkScript,
	})
	for _, out := range addOutputs {
		tx.AddTxOut(out)
	}
	for _, out := range opReturnOutputs {
		tx.AddTxOut(out)
	}

	inputWitnesses := make(map[int]wire.TxWitness, len(inputWitness))
	for i, witnessStr := range inputWitness {
		idx, witness, err := parseInputWitness(witnessStr)
		if err != nil {
			return fmt.Errorf("add_input_witness %d: %w", i, err)
		}
		if idx == 0 {
			return fmt.Errorf("add_input_witness %d: input index 0 reserved for HTLC", i)
		}
		if _, exists := inputWitnesses[idx]; exists {
			return fmt.Errorf("add_input_witness %d: duplicate input index %d", i, idx)
		}
		inputWitnesses[idx] = witness
	}
	for idx := range inputWitnesses {
		if idx < 0 || idx >= len(tx.TxIn) {
			return fmt.Errorf("add_input_witness: input index %d out of range", idx)
		}
	}

	signMethod := signrpc.SignMethod_SIGN_METHOD_WITNESS_V0
	if taproot {
		signMethod = signrpc.SignMethod_SIGN_METHOD_TAPROOT_SCRIPT_SPEND
	}
	signReq, err := buildSignReq(
		tx, htlcPkScript, outputValueSat, witnessScript,
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
	localSig := signResp.RawSigs[0]

	witness, err := buildWitness(
		localSig, senderSig, sighash, senderSigHash, preimage,
		witnessScript, controlBlock, taproot,
	)
	if err != nil {
		return err
	}
	tx.TxIn[0].Witness = witness
	for idx, wit := range inputWitnesses {
		tx.TxIn[idx].Witness = wit
	}
	if err := applyTaprootSignatures(tx, *outpoint, htlcPkScript, outputValueSat, addInputs, taprootSigInputs, inputWitnesses); err != nil {
		return err
	}

	totalInputValue := outputValueSat
	for _, in := range addInputs {
		totalInputValue += in.value
	}

	totalOutputValue := secondLevelValueSat
	for _, out := range addOutputs {
		totalOutputValue += out.Value
	}
	for _, out := range opReturnOutputs {
		totalOutputValue += out.Value
	}

	fee := totalInputValue - totalOutputValue
	if fee < 0 {
		return fmt.Errorf("total outputs exceed inputs (%d < %d)",
			totalInputValue, totalOutputValue)
	}

	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		return fmt.Errorf("serialize tx: %w", err)
	}
	rawHex := hex.EncodeToString(buf.Bytes())

	fmt.Printf("Second-level output: %d sat\n", secondLevelValueSat)
	fmt.Printf("Fee: %d sat\n", fee)
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
		return nil, fmt.Errorf("outpoint must be txid:vout")
	}

	hash, err := chainhash.NewHashFromStr(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid txid: %w", err)
	}

	vout, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid vout: %w", err)
	}

	return &wire.OutPoint{
		Hash:  *hash,
		Index: uint32(vout),
	}, nil
}

func parseOptionalHex(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	return hex.DecodeString(s)
}

func parseSigHash(s string, taproot bool) (txscript.SigHashType, error) {
	if s == "" {
		if taproot {
			return txscript.SigHashDefault, nil
		}
		return txscript.SigHashAll, nil
	}

	switch strings.ToLower(s) {
	case "all":
		return txscript.SigHashAll, nil
	case "single":
		return txscript.SigHashSingle, nil
	case "single_anyonecanpay":
		return txscript.SigHashSingle | txscript.SigHashAnyOneCanPay, nil
	case "all_anyonecanpay":
		return txscript.SigHashAll | txscript.SigHashAnyOneCanPay, nil
	case "default":
		if !taproot {
			return 0, fmt.Errorf("default sighash requires taproot")
		}
		return txscript.SigHashDefault, nil
	}

	base := 10
	num := s
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		base = 16
		num = s[2:]
	}
	val, err := strconv.ParseUint(num, base, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid sighash value")
	}
	return txscript.SigHashType(val), nil
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

func parseTaprootSigInput(s string) (taprootSigInput, error) {
	parts := strings.Split(s, ":")
	if len(parts) < 5 || len(parts) > 6 {
		return taprootSigInput{}, fmt.Errorf("format index:privkey:pk_script:tapscript:control_block[:sighash]")
	}

	idx, err := strconv.Atoi(parts[0])
	if err != nil || idx < 0 {
		return taprootSigInput{}, fmt.Errorf("invalid input index")
	}

	privKeyBytes, err := hex.DecodeString(parts[1])
	if err != nil {
		return taprootSigInput{}, fmt.Errorf("invalid privkey: %w", err)
	}
	privKey, _ := btcec.PrivKeyFromBytes(privKeyBytes)

	pkScript, err := hex.DecodeString(parts[2])
	if err != nil {
		return taprootSigInput{}, fmt.Errorf("invalid pk_script: %w", err)
	}

	tapscript, err := hex.DecodeString(parts[3])
	if err != nil {
		return taprootSigInput{}, fmt.Errorf("invalid tapscript: %w", err)
	}

	ctrl, err := hex.DecodeString(parts[4])
	if err != nil {
		return taprootSigInput{}, fmt.Errorf("invalid control_block: %w", err)
	}

	sighash := txscript.SigHashDefault
	if len(parts) == 6 {
		sighash, err = parseSigHash(parts[5], true)
		if err != nil {
			return taprootSigInput{}, fmt.Errorf("invalid sighash: %w", err)
		}
	}

	return taprootSigInput{
		index:        idx,
		privKey:      privKey,
		pkScript:     pkScript,
		tapscript:    tapscript,
		controlBlock: ctrl,
		sighash:      sighash,
	}, nil
}

func parseInputWitness(s string) (int, wire.TxWitness, error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return 0, nil, fmt.Errorf("witness must be index:hex,hex,...")
	}

	idx, err := strconv.Atoi(parts[0])
	if err != nil || idx < 0 {
		return 0, nil, fmt.Errorf("invalid input index")
	}

	if parts[1] == "" {
		return idx, wire.TxWitness{}, nil
	}

	itemStrs := strings.Split(parts[1], ",")
	witness := make(wire.TxWitness, 0, len(itemStrs))
	for _, item := range itemStrs {
		if item == "" {
			witness = append(witness, []byte{})
			continue
		}
		b, err := hex.DecodeString(item)
		if err != nil {
			return 0, nil, fmt.Errorf("invalid witness item %q: %w", item, err)
		}
		witness = append(witness, b)
	}

	return idx, witness, nil
}

func applyTaprootSignatures(tx *wire.MsgTx, htlcOutpoint wire.OutPoint,
	htlcPkScript []byte, htlcValue int64, addInputs []additionalInput,
	sigInputs []taprootSigInput, inputWitnesses map[int]wire.TxWitness) error {

	if len(sigInputs) == 0 {
		return nil
	}

	prevOuts := txscript.NewMultiPrevOutFetcher(nil)
	prevOuts.AddPrevOut(htlcOutpoint, &wire.TxOut{
		Value:    htlcValue,
		PkScript: htlcPkScript,
	})

	for i := range addInputs {
		if addInputs[i].value <= 0 || len(addInputs[i].pkScript) == 0 {
			continue
		}
		prevOuts.AddPrevOut(addInputs[i].txIn.PreviousOutPoint, &wire.TxOut{
			Value:    addInputs[i].value,
			PkScript: addInputs[i].pkScript,
		})
	}

	for i, entry := range sigInputs {
		if entry.index == 0 {
			return fmt.Errorf("add_input_taproot_sig %d: input index 0 reserved for HTLC", i)
		}
		if entry.index < 0 || entry.index >= len(tx.TxIn) {
			return fmt.Errorf("add_input_taproot_sig %d: input index %d out of range", i, entry.index)
		}
		if _, exists := inputWitnesses[entry.index]; exists {
			return fmt.Errorf("add_input_taproot_sig %d: witness already set for input %d", i, entry.index)
		}
		addIdx := entry.index - 1
		if addIdx < 0 || addIdx >= len(addInputs) {
			return fmt.Errorf("add_input_taproot_sig %d: input index %d not in extra inputs", i, entry.index)
		}
		if addInputs[addIdx].value <= 0 {
			return fmt.Errorf("add_input_taproot_sig %d: missing input value for index %d", i, entry.index)
		}
		if len(addInputs[addIdx].pkScript) == 0 {
			addInputs[addIdx].pkScript = entry.pkScript
			prevOuts.AddPrevOut(addInputs[addIdx].txIn.PreviousOutPoint, &wire.TxOut{
				Value:    addInputs[addIdx].value,
				PkScript: entry.pkScript,
			})
		}
	}

	sigHashes := txscript.NewTxSigHashes(tx, prevOuts)
	for i, entry := range sigInputs {
		if entry.sighash&txscript.SigHashAnyOneCanPay != txscript.SigHashAnyOneCanPay {
			for idx := range tx.TxIn {
				op := tx.TxIn[idx].PreviousOutPoint
				if prevOuts.FetchPrevOutput(op) == nil {
					return fmt.Errorf("missing prevout for input %d (set pk_script or use sighash anyonecanpay)", idx)
				}
			}
		}

		tapLeaf := txscript.NewBaseTapLeaf(entry.tapscript)
		sigHash, err := txscript.CalcTapscriptSignaturehash(
			sigHashes, entry.sighash, tx, entry.index, prevOuts, tapLeaf,
		)
		if err != nil {
			return fmt.Errorf("add_input_taproot_sig %d: sighash: %w", i, err)
		}

		sig, err := schnorr.Sign(entry.privKey, sigHash)
		if err != nil {
			return fmt.Errorf("add_input_taproot_sig %d: sign: %w", i, err)
		}
		sigBytes := sig.Serialize()
		if entry.sighash != txscript.SigHashDefault {
			sigBytes = append(sigBytes, byte(entry.sighash))
		}

		tx.TxIn[entry.index].Witness = wire.TxWitness{
			sigBytes,
			entry.tapscript,
			entry.controlBlock,
		}
	}

	return nil
}

func parseExtraOutput(s string) (*wire.TxOut, error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("add_output must be value_sats:pk_script_hex")
	}

	val, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid value: %w", err)
	}
	if val < 0 {
		return nil, fmt.Errorf("value must be >= 0")
	}

	pkScript, err := hex.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid pk_script: %w", err)
	}

	return &wire.TxOut{
		Value:    val,
		PkScript: pkScript,
	}, nil
}

func buildOpReturnOutput(dataHex string) (*wire.TxOut, error) {
	data, err := hex.DecodeString(dataHex)
	if err != nil {
		return nil, fmt.Errorf("invalid op_return data: %w", err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("op_return data empty")
	}

	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_RETURN)
	builder.AddData(data)

	script, err := builder.Script()
	if err != nil {
		return nil, fmt.Errorf("build op_return: %w", err)
	}

	return &wire.TxOut{
		Value:    0,
		PkScript: script,
	}, nil
}

func buildSignReq(tx *wire.MsgTx, htlcPkScript []byte, outputValueSat int64,
	witnessScript, singleTweak []byte, keyFamily, keyIndex int,
	sighash txscript.SigHashType, signMethod signrpc.SignMethod,
	taproot bool) (*signrpc.SignReq, error) {

	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		return nil, fmt.Errorf("serialize tx: %w", err)
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

func buildWitness(localSig, senderSig []byte, sighash, senderSigHash txscript.SigHashType,
	preimage, witnessScript, controlBlock []byte, taproot bool) (wire.TxWitness, error) {

	if taproot {
		if len(controlBlock) == 0 {
			return nil, fmt.Errorf("control_block required for taproot")
		}

		return wire.TxWitness{
			appendTaprootSig(senderSig, senderSigHash),
			appendTaprootSig(localSig, sighash),
			preimage,
			witnessScript,
			controlBlock,
		}, nil
	}

	return wire.TxWitness{
		nil,
		appendECDSASig(senderSig, senderSigHash),
		appendECDSASig(localSig, sighash),
		preimage,
		witnessScript,
	}, nil
}

func appendECDSASig(sig []byte, sighash txscript.SigHashType) []byte {
	sigBytes := append([]byte{}, sig...)
	return append(sigBytes, byte(sighash))
}

func appendTaprootSig(sig []byte, sighash txscript.SigHashType) []byte {
	sigBytes := append([]byte{}, sig...)
	if sighash != txscript.SigHashDefault {
		sigBytes = append(sigBytes, byte(sighash))
	}
	return sigBytes
}

type jsonInput struct {
	Hash     chainhash.Hash
	Vout     uint32
	Sequence *uint32
}

type walletUtxo struct {
	value    int64
	pkScript []byte
}

func parseInputsJSON(s string) ([]jsonInput, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}

	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()

	var raw []map[string]interface{}
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("add_inputs_json: %w", err)
	}

	inputs := make([]jsonInput, 0, len(raw))
	for i, obj := range raw {
		txidRaw, ok := obj["txid"]
		if !ok {
			return nil, fmt.Errorf("add_inputs_json[%d]: txid required", i)
		}
		txid, ok := txidRaw.(string)
		if !ok || txid == "" {
			return nil, fmt.Errorf("add_inputs_json[%d]: txid must be string", i)
		}

		voutRaw, ok := obj["vout"]
		if !ok {
			return nil, fmt.Errorf("add_inputs_json[%d]: vout required", i)
		}
		vout, err := parseJSONUint(voutRaw, "vout")
		if err != nil {
			return nil, fmt.Errorf("add_inputs_json[%d]: %w", i, err)
		}

		hash, err := chainhash.NewHashFromStr(txid)
		if err != nil {
			return nil, fmt.Errorf("add_inputs_json[%d]: invalid txid: %w", i, err)
		}

		var seqPtr *uint32
		if seqRaw, ok := obj["sequence"]; ok {
			seq, err := parseJSONUint(seqRaw, "sequence")
			if err != nil {
				return nil, fmt.Errorf("add_inputs_json[%d]: %w", i, err)
			}
			seq32 := uint32(seq)
			seqPtr = &seq32
		}

		inputs = append(inputs, jsonInput{
			Hash:     *hash,
			Vout:     uint32(vout),
			Sequence: seqPtr,
		})
	}

	return inputs, nil
}

func parseOutputsJSON(s string, params *chaincfg.Params) ([]*wire.TxOut, []*wire.TxOut, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil, nil
	}

	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()

	var raw interface{}
	if err := dec.Decode(&raw); err != nil {
		return nil, nil, fmt.Errorf("add_outputs_json: %w", err)
	}

	var (
		outputs   []*wire.TxOut
		opReturns []*wire.TxOut
	)

	switch v := raw.(type) {
	case []interface{}:
		for i, elem := range v {
			obj, ok := elem.(map[string]interface{})
			if !ok {
				return nil, nil, fmt.Errorf("add_outputs_json[%d]: object required", i)
			}
			if err := parseOutputObject(obj, params, &outputs, &opReturns); err != nil {
				return nil, nil, fmt.Errorf("add_outputs_json[%d]: %w", i, err)
			}
		}

	case map[string]interface{}:
		if err := parseOutputObject(v, params, &outputs, &opReturns); err != nil {
			return nil, nil, fmt.Errorf("add_outputs_json: %w", err)
		}

	default:
		return nil, nil, fmt.Errorf("add_outputs_json must be array or object")
	}

	return outputs, opReturns, nil
}

func parseOutputObject(obj map[string]interface{}, params *chaincfg.Params,
	outputs, opReturns *[]*wire.TxOut) error {

	if dataRaw, ok := obj["data"]; ok {
		data, ok := dataRaw.(string)
		if !ok {
			return fmt.Errorf("data must be hex string")
		}
		txOut, err := buildOpReturnOutput(data)
		if err != nil {
			return err
		}
		*opReturns = append(*opReturns, txOut)
	}

	if addrRaw, ok := obj["address"]; ok {
		addr, ok := addrRaw.(string)
		if !ok || addr == "" {
			return fmt.Errorf("address must be string")
		}
		amtRaw, ok := obj["amount"]
		if !ok {
			return fmt.Errorf("amount required with address")
		}
		amtSat, err := parseJSONAmount(amtRaw)
		if err != nil {
			return err
		}
		txOut, err := buildAddressOutput(addr, amtSat, params)
		if err != nil {
			return err
		}
		*outputs = append(*outputs, txOut)
		return nil
	}

	for key, val := range obj {
		if key == "data" {
			continue
		}
		amtSat, err := parseJSONAmount(val)
		if err != nil {
			return err
		}
		txOut, err := buildAddressOutput(key, amtSat, params)
		if err != nil {
			return err
		}
		*outputs = append(*outputs, txOut)
	}

	return nil
}

func buildAddressOutput(addr string, amountSat int64,
	params *chaincfg.Params) (*wire.TxOut, error) {

	if amountSat < 0 {
		return nil, fmt.Errorf("amount must be >= 0")
	}

	decoded, err := btcutil.DecodeAddress(addr, params)
	if err != nil {
		return nil, fmt.Errorf("invalid address %q: %w", addr, err)
	}

	pkScript, err := txscript.PayToAddrScript(decoded)
	if err != nil {
		return nil, fmt.Errorf("p2addr script: %w", err)
	}

	return &wire.TxOut{
		Value:    amountSat,
		PkScript: pkScript,
	}, nil
}

func parseJSONUint(v interface{}, field string) (uint64, error) {
	switch t := v.(type) {
	case json.Number:
		return strconv.ParseUint(t.String(), 10, 32)
	case float64:
		if t < 0 {
			return 0, fmt.Errorf("%s must be >= 0", field)
		}
		return uint64(t), nil
	case string:
		return strconv.ParseUint(t, 10, 32)
	default:
		return 0, fmt.Errorf("%s must be number", field)
	}
}

func parseJSONAmount(v interface{}) (int64, error) {
	switch t := v.(type) {
	case json.Number:
		return parseAmountString(t.String())
	case float64:
		return btcToSat(t)
	case string:
		return parseAmountString(t)
	default:
		return 0, fmt.Errorf("amount must be number or string")
	}
}

func parseAmountString(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if strings.HasSuffix(s, "sat") {
		s = strings.TrimSuffix(s, "sat")
		s = strings.TrimSpace(s)
		return strconv.ParseInt(s, 10, 64)
	}
	if strings.HasSuffix(s, "sats") {
		s = strings.TrimSuffix(s, "sats")
		s = strings.TrimSpace(s)
		return strconv.ParseInt(s, 10, 64)
	}

	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, err
	}
	return btcToSat(f)
}

func btcToSat(btc float64) (int64, error) {
	amt, err := btcutil.NewAmount(btc)
	if err != nil {
		return 0, err
	}
	return int64(amt), nil
}

func networkParams(network string) (*chaincfg.Params, error) {
	switch strings.ToLower(network) {
	case "mainnet", "main":
		return &chaincfg.MainNetParams, nil
	case "testnet", "testnet3", "testnet4":
		return &chaincfg.TestNet3Params, nil
	case "regtest", "regression":
		return &chaincfg.RegressionNetParams, nil
	case "simnet":
		return &chaincfg.SimNetParams, nil
	default:
		return nil, fmt.Errorf("unknown network %q", network)
	}
}

func outpointKey(hash chainhash.Hash, index uint32) string {
	return fmt.Sprintf("%s:%d", hash.String(), index)
}

func fetchWalletUtxos(ctx context.Context, conn *grpc.ClientConn) (map[string]walletUtxo, error) {
	client := walletrpc.NewWalletKitClient(conn)
	resp, err := client.ListUnspent(ctx, &walletrpc.ListUnspentRequest{
		MinConfs:        0,
		MaxConfs:        0,
		UnconfirmedOnly: false,
	})
	if err != nil {
		return nil, fmt.Errorf("listunspent: %w", err)
	}

	utxos := make(map[string]walletUtxo, len(resp.Utxos))
	for _, u := range resp.Utxos {
		if u.Outpoint == nil {
			continue
		}
		pk, err := hex.DecodeString(u.PkScript)
		if err != nil {
			return nil, fmt.Errorf("decode pk_script: %w", err)
		}
		key := fmt.Sprintf("%s:%d", u.Outpoint.TxidStr, u.Outpoint.OutputIndex)
		utxos[key] = walletUtxo{
			value:    u.AmountSat,
			pkScript: pk,
		}
	}

	return utxos, nil
}
