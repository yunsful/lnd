package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcutil/psbt"
)

func main() {
	var (
		psbtB64     = flag.String("psbt", "", "base64 PSBT")
		seqStr      = flag.String("sequence", "", "sequence number (decimal or 0x hex)")
		inputIdxStr = flag.String("input_indices", "", "comma-separated input indexes to update (default: all)")
	)
	flag.Parse()

	if *psbtB64 == "" || *seqStr == "" {
		fmt.Fprintln(os.Stderr, "psbt and sequence are required")
		flag.Usage()
		os.Exit(1)
	}

	sequence, err := parseSequence(*seqStr)
	if err != nil {
		fail("invalid sequence: %v", err)
	}

	packet, err := psbt.NewFromRawBytes(bytes.NewReader([]byte(*psbtB64)), true)
	if err != nil {
		fail("decode psbt: %v", err)
	}
	if packet.UnsignedTx == nil || len(packet.UnsignedTx.TxIn) == 0 {
		fail("psbt has no inputs")
	}

	indices, err := parseIndices(*inputIdxStr, len(packet.UnsignedTx.TxIn))
	if err != nil {
		fail("invalid input_indices: %v", err)
	}

	if len(indices) == 0 {
		for i := range packet.UnsignedTx.TxIn {
			packet.UnsignedTx.TxIn[i].Sequence = sequence
		}
	} else {
		for _, idx := range indices {
			packet.UnsignedTx.TxIn[idx].Sequence = sequence
		}
	}

	encoded, err := packet.B64Encode()
	if err != nil {
		fail("encode psbt: %v", err)
	}

	fmt.Println(encoded)
}

func parseSequence(s string) (uint32, error) {
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		val, err := strconv.ParseUint(s[2:], 16, 32)
		return uint32(val), err
	}
	val, err := strconv.ParseUint(s, 10, 32)
	return uint32(val), err
}

func parseIndices(s string, max int) ([]int, error) {
	if s == "" {
		return nil, nil
	}

	parts := strings.Split(s, ",")
	indices := make([]int, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		idx, err := strconv.Atoi(part)
		if err != nil {
			return nil, err
		}
		if idx < 0 || idx >= max {
			return nil, fmt.Errorf("index %d out of range", idx)
		}
		indices = append(indices, idx)
	}

	return indices, nil
}

func fail(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
