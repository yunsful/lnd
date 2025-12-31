package main

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/btcsuite/btcd/wire"
)

// htlcmerge copies a pre-built witness from a raw transaction into a finalized
// transaction (e.g. after lnd signs additional inputs) to produce a final hex.
// This is needed when the HTLC input was already signed before PSBT finalization.
func main() {
	rawHex := flag.String("raw_tx", "", "raw transaction hex (with HTLC witness)")
	finalHex := flag.String("final_tx", "", "final transaction hex (with other inputs signed)")
	htlcIdx := flag.Int("htlc_input_index", 0, "index of the HTLC input whose witness should be preserved")
	flag.Parse()

	if *rawHex == "" || *finalHex == "" {
		fail("raw_tx and final_tx are required")
	}

	rawTx, err := parseTx(*rawHex)
	if err != nil {
		fail("parse raw_tx: %v", err)
	}
	finalTx, err := parseTx(*finalHex)
	if err != nil {
		fail("parse final_tx: %v", err)
	}

	if *htlcIdx < 0 || *htlcIdx >= len(rawTx.TxIn) || *htlcIdx >= len(finalTx.TxIn) {
		fail("htlc_input_index out of range")
	}

	// Preserve the HTLC witness from the original raw tx.
	finalTx.TxIn[*htlcIdx].Witness = rawTx.TxIn[*htlcIdx].Witness

	merged, err := serializeTx(finalTx)
	if err != nil {
		fail("serialize merged tx: %v", err)
	}

	fmt.Println(merged)
}

func parseTx(hexStr string) (*wire.MsgTx, error) {
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, err
	}

	var tx wire.MsgTx
	if err := tx.Deserialize(bytes.NewReader(b)); err != nil {
		return nil, err
	}
	return &tx, nil
}

func serializeTx(tx *wire.MsgTx) (string, error) {
	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf.Bytes()), nil
}

func fail(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
