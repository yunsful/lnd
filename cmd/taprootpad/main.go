package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/lightningnetwork/lnd/input"
)

func main() {
	network := flag.String("network", "mainnet", "network: mainnet|testnet|signet|regtest")
	pushSize := flag.Int("push_size", 520, "size of each data push (1-520)")
	pushCount := flag.Int("push_count", 1, "number of push+drop ops")
	randomPad := flag.Bool("random_pad", false, "fill push data with random bytes")
	randomPerPush := flag.Bool("random_per_push", false, "randomize each push separately (requires random_pad)")
	sigPubKeyHex := flag.String("sig_pubkey", "", "hex pubkey for OP_CHECKSIG (32-byte x-only or 33-byte compressed)")
	flag.Parse()

	params, err := networkParams(*network)
	if err != nil {
		fail(err)
	}
	if *pushSize < 1 || *pushSize > txscript.MaxScriptElementSize {
		fail(fmt.Errorf("push_size must be 1..%d", txscript.MaxScriptElementSize))
	}
	if *pushCount < 0 {
		fail(fmt.Errorf("push_count must be >= 0"))
	}

	builder := txscript.NewScriptBuilder()
	var sigPubKey []byte
	if *sigPubKeyHex != "" {
		raw, err := hex.DecodeString(*sigPubKeyHex)
		if err != nil {
			fail(fmt.Errorf("sig_pubkey: %w", err))
		}
		switch len(raw) {
		case schnorr.PubKeyBytesLen:
			if _, err := schnorr.ParsePubKey(raw); err != nil {
				fail(fmt.Errorf("sig_pubkey: %w", err))
			}
			sigPubKey = raw
		case btcec.PubKeyBytesLenCompressed:
			pub, err := btcec.ParsePubKey(raw)
			if err != nil {
				fail(fmt.Errorf("sig_pubkey: %w", err))
			}
			sigPubKey = schnorr.SerializePubKey(pub)
		default:
			fail(fmt.Errorf("sig_pubkey must be 32 or 33 bytes"))
		}
		builder.AddData(sigPubKey)
		builder.AddOp(txscript.OP_CHECKSIGVERIFY)
	}

	var pad []byte
	if *randomPad && !*randomPerPush {
		pad = make([]byte, *pushSize)
		if _, err := rand.Read(pad); err != nil {
			fail(fmt.Errorf("random pad: %w", err))
		}
	}

	for i := 0; i < *pushCount; i++ {
		if *randomPad && *randomPerPush {
			pad = make([]byte, *pushSize)
			if _, err := rand.Read(pad); err != nil {
				fail(fmt.Errorf("random pad: %w", err))
			}
		} else if !*randomPad {
			if pad == nil {
				pad = make([]byte, *pushSize)
			}
		}
		builder.AddData(pad)
		builder.AddOp(txscript.OP_DROP)
	}
	builder.AddOp(txscript.OP_1)

	tapscript, err := builder.Script()
	if err != nil {
		fail(fmt.Errorf("build tapscript: %w", err))
	}

	leaf := txscript.NewBaseTapLeaf(tapscript)
	tree := txscript.AssembleTaprootScriptTree(leaf)
	ctrlBlock := input.MakeTaprootCtrlBlock(
		tapscript, &input.TaprootNUMSKey, tree,
	)
	ctrlBytes, err := ctrlBlock.ToBytes()
	if err != nil {
		fail(fmt.Errorf("control block: %w", err))
	}

	rootHash := tree.RootNode.TapHash()
	tapKey := txscript.ComputeTaprootOutputKey(
		&input.TaprootNUMSKey, rootHash[:],
	)
	pkScript, err := txscript.PayToTaprootScript(tapKey)
	if err != nil {
		fail(fmt.Errorf("pk_script: %w", err))
	}
	addr, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(tapKey), params,
	)
	if err != nil {
		fail(fmt.Errorf("address: %w", err))
	}

	fmt.Printf("address: %s\n", addr.String())
	fmt.Printf("pk_script_hex: %s\n", hex.EncodeToString(pkScript))
	fmt.Printf("tapscript_len: %d\n", len(tapscript))
	fmt.Printf("tapscript_hex: %s\n", hex.EncodeToString(tapscript))
	fmt.Printf("control_block_len: %d\n", len(ctrlBytes))
	fmt.Printf("control_block_hex: %s\n", hex.EncodeToString(ctrlBytes))
	if len(sigPubKey) > 0 {
		fmt.Printf("sig_pubkey_xonly: %s\n", hex.EncodeToString(sigPubKey))
		fmt.Printf("add_input_witness: 1:<sig_hex>,%s,%s\n",
			hex.EncodeToString(tapscript),
			hex.EncodeToString(ctrlBytes),
		)
	} else {
		fmt.Printf("add_input_witness: 1:%s,%s\n",
			hex.EncodeToString(tapscript),
			hex.EncodeToString(ctrlBytes),
		)
	}
}

func networkParams(network string) (*chaincfg.Params, error) {
	switch network {
	case "mainnet":
		return &chaincfg.MainNetParams, nil
	case "testnet":
		return &chaincfg.TestNet3Params, nil
	case "regtest":
		return &chaincfg.RegressionNetParams, nil
	case "signet":
		return &chaincfg.SigNetParams, nil
	default:
		return nil, fmt.Errorf("unknown network %q", network)
	}
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}
