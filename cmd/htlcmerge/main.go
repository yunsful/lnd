package main

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/btcsuite/btcd/wire"
)

type intSlice []int

func (s *intSlice) String() string {
	return fmt.Sprint([]int(*s))
}

func (s *intSlice) Set(v string) error {
	idx, err := strconv.Atoi(v)
	if err != nil {
		return err
	}
	*s = append(*s, idx)
	return nil
}

// htlcmerge copies a pre-built witness from a raw transaction into a finalized
// transaction (e.g. after lnd signs additional inputs) to produce a final hex.
// This is needed when the HTLC input was already signed before PSBT finalization.
func main() {
	rawHex := flag.String("raw_tx", "", "raw transaction hex (with HTLC witness)")
	finalHex := flag.String("final_tx", "", "final transaction hex (with other inputs signed)")
	htlcIdx := flag.Int("htlc_input_index", 0, "index of the HTLC input whose witness should be preserved")
	preserveIdxs := intSlice{}
	flag.Var(&preserveIdxs, "preserve_input_index", "input index to preserve witness from raw tx (repeatable)")
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

	idxSet := map[int]struct{}{}
	if *htlcIdx >= 0 {
		idxSet[*htlcIdx] = struct{}{}
	}
	for _, idx := range preserveIdxs {
		idxSet[idx] = struct{}{}
	}
	if len(idxSet) == 0 {
		fail("no input indices to preserve")
	}

	for idx := range idxSet {
		if idx < 0 || idx >= len(rawTx.TxIn) || idx >= len(finalTx.TxIn) {
			fail("input index %d out of range", idx)
		}
		if len(rawTx.TxIn[idx].Witness) == 0 {
			continue
		}
		finalTx.TxIn[idx].Witness = rawTx.TxIn[idx].Witness
	}

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
