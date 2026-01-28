package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

func main() {
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		fail(fmt.Errorf("generate privkey: %w", err))
	}

	privBytes := priv.Serialize()
	pub := priv.PubKey()
	pubCompressed := pub.SerializeCompressed()
	pubXOnly := schnorr.SerializePubKey(pub)

	fmt.Printf("privkey_hex: %s\n", hex.EncodeToString(privBytes))
	fmt.Printf("pubkey_compressed_hex: %s\n", hex.EncodeToString(pubCompressed))
	fmt.Printf("pubkey_xonly_hex: %s\n", hex.EncodeToString(pubXOnly))
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}
