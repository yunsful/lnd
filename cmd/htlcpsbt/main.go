package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/lightningnetwork/lnd/macaroons"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"gopkg.in/macaroon.v2"
)

// This helper builds a PSBT that preserves a pre-signed HTLC input as a
// finalized witness. If wallet UTXOs are present as additional inputs, it can
// attach witness_utxo data so lnd can sign them.
const (
	defaultRPCHost      = "localhost:10009"
	defaultTLSCert      = "/Library/Application Support/Lnd/tls.cert"
	defaultMacaroonPath = "/Library/Application Support/Lnd/data/chain/bitcoin/mainnet/admin.macaroon"
)

func main() {
	var (
		rawTxHex  = flag.String("raw_tx", "", "raw tx hex (HTLC input already signed)")
		htlcValue = flag.Int64("htlc_value_sat", 0, "HTLC input value (sat)")
		htlcPkHex = flag.String("htlc_pk_script", "", "HTLC pk_script hex")
		utxoValue = flag.Int64("utxo_value_sat", 0, "wallet UTXO value (sat)")
		utxoPkHex = flag.String("utxo_pk_script", "", "wallet UTXO pk_script hex")

		rpcServer = flag.String("rpcserver", defaultRPCHost, "lnd gRPC host:port")
		tlsPath   = flag.String("tlscert", "", "path to lnd tls.cert")
		macPath   = flag.String("macaroon", "", "path to admin macaroon")
	)
	flag.Parse()

	if *rawTxHex == "" || *htlcValue <= 0 || *htlcPkHex == "" {
		fmt.Fprintf(os.Stderr, "missing required flags\n")
		flag.Usage()
		os.Exit(1)
	}

	rawBytes, err := hex.DecodeString(*rawTxHex)
	if err != nil {
		fail("decode raw tx: %v", err)
	}

	var tx wire.MsgTx
	if err := tx.Deserialize(bytes.NewReader(rawBytes)); err != nil {
		fail("parse tx: %v", err)
	}

	if len(tx.TxIn) == 0 {
		fail("transaction must have at least one input")
	}

	htlcPk, err := hex.DecodeString(*htlcPkHex)
	if err != nil {
		fail("decode htlc pk_script: %v", err)
	}

	// Copy tx without any existing witnesses/scripts.
	unsigned := tx
	for i := range unsigned.TxIn {
		unsigned.TxIn[i].SignatureScript = nil
		unsigned.TxIn[i].Witness = nil
	}

	p, err := psbt.NewFromUnsignedTx(&unsigned)
	if err != nil {
		fail("new psbt: %v", err)
	}

	// Finalize HTLC input (index 0) with its existing witness and prev out.
	var witBuf bytes.Buffer
	if err := psbt.WriteTxWitness(&witBuf, tx.TxIn[0].Witness); err != nil {
		fail("encode htlc witness: %v", err)
	}
	p.Inputs[0].FinalScriptWitness = witBuf.Bytes()
	p.Inputs[0].WitnessUtxo = &wire.TxOut{
		Value:    *htlcValue,
		PkScript: htlcPk,
	}

	if len(p.Inputs) > 1 {
		if *utxoValue > 0 && *utxoPkHex != "" {
			utxoPk, err := hex.DecodeString(*utxoPkHex)
			if err != nil {
				fail("decode utxo pk_script: %v", err)
			}
			p.Inputs[1].WitnessUtxo = &wire.TxOut{
				Value:    *utxoValue,
				PkScript: utxoPk,
			}
		}

		needsLookup := false
		for i := 1; i < len(p.Inputs); i++ {
			if p.Inputs[i].WitnessUtxo == nil {
				needsLookup = true
				break
			}
		}

		if needsLookup {
			if *tlsPath == "" || *macPath == "" {
				homeDir, err := os.UserHomeDir()
				if err != nil {
					fail("unable to detect home dir: %v", err)
				}
				base := filepath.Join(homeDir, "")
				if *tlsPath == "" {
					*tlsPath = filepath.Join(base, defaultTLSCert)
				}
				if *macPath == "" {
					*macPath = filepath.Join(base, defaultMacaroonPath)
				}
			}

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			conn, err := dialLnd(ctx, *rpcServer, *tlsPath, *macPath)
			if err != nil {
				fail("dial lnd: %v", err)
			}
			defer conn.Close()

			utxos, err := fetchWalletUtxos(ctx, conn)
			if err != nil {
				fail("listunspent: %v", err)
			}

			for i := 1; i < len(p.Inputs); i++ {
				if p.Inputs[i].WitnessUtxo != nil {
					continue
				}
				op := tx.TxIn[i].PreviousOutPoint
				key := fmt.Sprintf("%s:%d", op.Hash.String(), op.Index)
				utxo, ok := utxos[key]
				if !ok {
					fail("wallet utxo not found for input %s", key)
				}
				p.Inputs[i].WitnessUtxo = &wire.TxOut{
					Value:    utxo.value,
					PkScript: utxo.pkScript,
				}
			}
		}
	}

	encoded, err := p.B64Encode()
	if err != nil {
		fail("encode psbt: %v", err)
	}

	fmt.Println(encoded)
}

func fail(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

type walletUtxo struct {
	value    int64
	pkScript []byte
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

func fetchWalletUtxos(ctx context.Context, conn *grpc.ClientConn) (map[string]walletUtxo, error) {
	client := walletrpc.NewWalletKitClient(conn)
	resp, err := client.ListUnspent(ctx, &walletrpc.ListUnspentRequest{
		MinConfs:        0,
		MaxConfs:        0,
		UnconfirmedOnly: false,
	})
	if err != nil {
		return nil, err
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
