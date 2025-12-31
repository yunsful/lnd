package main

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
)

// This helper builds a PSBT that preserves a pre-signed HTLC input as a
// finalized witness. If a wallet UTXO is present at index 1, it also attaches
// witness_utxo data so lnd can sign it. Additional inputs are left untouched.
func main() {
	var (
		rawTxHex  = flag.String("raw_tx", "", "raw tx hex (HTLC input already signed)")
		htlcValue = flag.Int64("htlc_value_sat", 0, "HTLC input value (sat)")
		htlcPkHex = flag.String("htlc_pk_script", "", "HTLC pk_script hex")
		utxoValue = flag.Int64("utxo_value_sat", 0, "wallet UTXO value (sat)")
		utxoPkHex = flag.String("utxo_pk_script", "", "wallet UTXO pk_script hex")
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

	// Wallet UTXO at index 1 needs witness_utxo so lnd can sign it.
	if len(p.Inputs) > 1 {
		if *utxoValue <= 0 || *utxoPkHex == "" {
			fail("utxo_value_sat and utxo_pk_script required when tx has 2 inputs")
		}
		utxoPk, err := hex.DecodeString(*utxoPkHex)
		if err != nil {
			fail("decode utxo pk_script: %v", err)
		}
		p.Inputs[1].WitnessUtxo = &wire.TxOut{
			Value:    *utxoValue,
			PkScript: utxoPk,
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
