package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/kvdb"
	"github.com/lightningnetwork/lnd/lncfg"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

const (
	defaultNetwork  = "mainnet"
	defaultBackend  = "bolt"
	defaultDBFile   = "channel.db"
	defaultSQLiteDB = "channel.sqlite"
)

func main() {
	var (
		network   = flag.String("network", defaultNetwork, "mainnet/testnet/regtest")
		dbDir     = flag.String("db_dir", "", "channel db directory (defaults to lnd data/graph/<network>)")
		dbBackend = flag.String("db_backend", defaultBackend, "bolt|sqlite")

		chanPointStr = flag.String("chan_point", "", "channel point <txid>:<vout>")
		htlcID       = flag.Uint64("htlc_id", 0, "HTLC ID (HtlcIndex)")
		incoming     = flag.Bool("incoming", true, "select incoming HTLC")
	)
	flag.Parse()

	if err := run(*network, *dbDir, *dbBackend, *chanPointStr, *htlcID, *incoming); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(network, dbDir, dbBackend, chanPointStr string, htlcID uint64,
	incoming bool) error {

	if chanPointStr == "" {
		return fmt.Errorf("chan_point is required")
	}

	chanPoint, err := parseOutPoint(chanPointStr)
	if err != nil {
		return err
	}

	if dbDir == "" {
		dbDir = defaultDBDir(network)
	}
	dbDir = lncfg.CleanAndExpandPath(dbDir)

	ctx := context.Background()
	backend, err := openBackend(ctx, dbBackend, dbDir)
	if err != nil {
		return err
	}
	defer backend.Close()

	db, err := channeldb.CreateWithBackend(
		backend, channeldb.OptionNoMigration(true),
	)
	if err != nil {
		return err
	}
	defer db.Close()

	chanState, err := db.ChannelStateDB().FetchChannel(*chanPoint)
	if err != nil {
		return err
	}

	htlc, err := findHTLC(chanState.LocalCommitment.Htlcs, htlcID, incoming)
	if err != nil {
		return err
	}
	if htlc.OutputIndex < 0 {
		return fmt.Errorf("htlc output is dust (output_index=%d)", htlc.OutputIndex)
	}
	if chanState.LocalCommitment.CommitTx == nil {
		return fmt.Errorf("local commit tx not found in channel state")
	}

	commitTx := chanState.LocalCommitment.CommitTx
	if int(htlc.OutputIndex) >= len(commitTx.TxOut) {
		return fmt.Errorf("htlc output index %d out of range (tx has %d outputs)",
			htlc.OutputIndex, len(commitTx.TxOut))
	}

	commitTxid := commitTx.TxHash()

	commitPoint, err := currentLocalCommitPoint(chanState)
	if err != nil {
		return err
	}

	keyRing := lnwallet.DeriveCommitmentKeys(
		commitPoint, lntypes.Local, chanState.ChanType,
		&chanState.LocalChanCfg, &chanState.RemoteChanCfg,
	)

	htlcPkScript, witnessScript, controlBlock, err := buildHtlcScripts(
		chanState.ChanType, htlc, keyRing,
	)
	if err != nil {
		return err
	}

	// Verify the script matches the commitment output.
	commitPk := commitTx.TxOut[htlc.OutputIndex].PkScript
	if !bytesEqual(commitPk, htlcPkScript) {
		fmt.Fprintf(os.Stderr, "warning: computed htlc_pk_script does not match "+
			"commitment output script\n")
	}

	senderSig := hex.EncodeToString(htlc.Signature)
	if senderSig == "" {
		return fmt.Errorf("sender signature missing for htlc %d", htlcID)
	}

	feePerKw := chainfee.SatPerKWeight(chanState.LocalCommitment.FeePerKw)
	htlcFee := lnwallet.HtlcSuccessFee(chanState.ChanType, feePerKw)
	secondLevelValue := int64(htlc.Amt.ToSatoshis() - htlcFee)
	if secondLevelValue <= 0 {
		return fmt.Errorf("second-level output value <= 0 (value=%d)", secondLevelValue)
	}

	csvDelay := uint32(chanState.LocalChanCfg.CsvDelay)
	leaseExpiry := uint32(0)
	if chanState.ChanType.HasLeaseExpiration() {
		leaseExpiry = chanState.ThawHeight
	}

	secondPk, secondWitness, secondCtrl, err := buildSecondLevelScripts(
		chanState, keyRing, csvDelay, leaseExpiry,
	)
	if err != nil {
		return err
	}

	sighash := lnwallet.HtlcSigHashType(chanState.ChanType)
	fmt.Printf("chan_point: %s\n", chanPointStr)
	fmt.Printf("commit_txid: %s\n", commitTxid.String())
	fmt.Printf("htlc_id: %d\n", htlcID)
	fmt.Printf("incoming: %t\n", incoming)
	fmt.Printf("htlc_output_index: %d\n", htlc.OutputIndex)
	fmt.Printf("htlc_outpoint: %s:%d\n", commitTxid.String(), htlc.OutputIndex)
	fmt.Printf("htlc_value_sat: %d\n", htlc.Amt.ToSatoshis())
	fmt.Printf("htlc_pk_script: %s\n", hex.EncodeToString(htlcPkScript))
	fmt.Printf("witness_script: %s\n", hex.EncodeToString(witnessScript))
	if len(controlBlock) > 0 {
		fmt.Printf("control_block: %s\n", hex.EncodeToString(controlBlock))
	}
	fmt.Printf("sender_sig: %s\n", senderSig)
	fmt.Printf("single_tweak: %s\n", hex.EncodeToString(keyRing.LocalHtlcKeyTweak))
	fmt.Printf("key_family: %d\n", chanState.LocalChanCfg.HtlcBasePoint.KeyLocator.Family)
	fmt.Printf("key_index: %d\n", chanState.LocalChanCfg.HtlcBasePoint.KeyLocator.Index)
	fmt.Printf("sighash: %s (0x%x)\n", sighashName(sighash), uint32(sighash))
	fmt.Printf("taproot: %t\n", chanState.ChanType.IsTaproot())
	fmt.Printf("csv_delay: %d\n", csvDelay)
	if leaseExpiry != 0 {
		fmt.Printf("lease_expiry: %d\n", leaseExpiry)
	}
	fmt.Printf("second_level_value_sat: %d\n", secondLevelValue)
	fmt.Printf("second_level_pk_script: %s\n", hex.EncodeToString(secondPk))
	if len(secondWitness) > 0 {
		fmt.Printf("second_level_witness_script: %s\n", hex.EncodeToString(secondWitness))
	}
	if len(secondCtrl) > 0 {
		fmt.Printf("second_level_control_block: %s\n", hex.EncodeToString(secondCtrl))
	}

	return nil
}

func defaultDBDir(network string) string {
	lndDir := btcutil.AppDataDir("lnd", false)
	dataDir := filepath.Join(lndDir, "data")
	return filepath.Join(
		dataDir, "graph", lncfg.NormalizeNetwork(network),
	)
}

func openBackend(ctx context.Context, backend, dir string) (kvdb.Backend, error) {
	switch strings.ToLower(backend) {
	case "bolt":
		dbPath := filepath.Join(dir, defaultDBFile)
		if !fileExists(dbPath) {
			return nil, fmt.Errorf("channel db not found: %s", dbPath)
		}

		return kvdb.GetBoltBackend(&kvdb.BoltBackendConfig{
			DBPath:            dir,
			DBFileName:        defaultDBFile,
			NoFreelistSync:    true,
			AutoCompact:       false,
			AutoCompactMinAge: kvdb.DefaultBoltAutoCompactMinAge,
			DBTimeout:         kvdb.DefaultDBTimeout,
			ReadOnly:          true,
		})

	case "sqlite":
		dbPath := filepath.Join(dir, defaultSQLiteDB)
		if !fileExists(dbPath) {
			return nil, fmt.Errorf("channel db not found: %s", dbPath)
		}
		if !kvdb.SqliteBackend {
			return nil, fmt.Errorf("sqlite backend not available in this build")
		}

		sqliteCfg := lncfg.GetSqliteConfigKVDB(lncfg.DefaultDB().Sqlite)
		return kvdb.Open(
			kvdb.SqliteBackendName, ctx, sqliteCfg, dir,
			lncfg.SqliteChannelDBName, lncfg.NSChannelDB,
		)

	default:
		return nil, fmt.Errorf("unknown db_backend %q", backend)
	}
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

func findHTLC(htlcs []channeldb.HTLC, htlcID uint64,
	incoming bool) (*channeldb.HTLC, error) {

	for i := range htlcs {
		if htlcs[i].HtlcIndex == htlcID && htlcs[i].Incoming == incoming {
			return &htlcs[i], nil
		}
	}

	return nil, fmt.Errorf("htlc %d (incoming=%t) not found in local commitment",
		htlcID, incoming)
}

func currentLocalCommitPoint(chanState *channeldb.OpenChannel) (*btcec.PublicKey,
	error) {

	secret, err := chanState.RevocationProducer.AtIndex(
		chanState.LocalCommitment.CommitHeight,
	)
	if err != nil {
		return nil, fmt.Errorf("derive revocation secret: %w", err)
	}

	return input.ComputeCommitmentPoint(secret[:]), nil
}

func buildHtlcScripts(chanType channeldb.ChannelType, htlc *channeldb.HTLC,
	keyRing *lnwallet.CommitmentKeyRing) ([]byte, []byte, []byte, error) {

	if chanType.IsTaproot() {
		var auxLeaf input.AuxTapLeaf
		htlcTree, err := lnwallet.GenTaprootHtlcScript(
			htlc.Incoming, lntypes.Local, htlc.RefundTimeout,
			htlc.RHash, keyRing, auxLeaf,
		)
		if err != nil {
			return nil, nil, nil, err
		}

		witnessScript, err := htlcTree.WitnessScriptForPath(
			input.ScriptPathSuccess,
		)
		if err != nil {
			return nil, nil, nil, err
		}

		ctrl, err := htlcTree.CtrlBlockForPath(
			input.ScriptPathSuccess,
		)
		if err != nil {
			return nil, nil, nil, err
		}
		ctrlBytes, err := ctrl.ToBytes()
		if err != nil {
			return nil, nil, nil, err
		}

		return htlcTree.PkScript(), witnessScript, ctrlBytes, nil
	}

	confirmedHtlcSpends := chanType.HasAnchors()
	witnessScript, err := input.ReceiverHTLCScript(
		htlc.RefundTimeout, keyRing.RemoteHtlcKey, keyRing.LocalHtlcKey,
		keyRing.RevocationKey, htlc.RHash[:], confirmedHtlcSpends,
	)
	if err != nil {
		return nil, nil, nil, err
	}

	pkScript, err := input.WitnessScriptHash(witnessScript)
	if err != nil {
		return nil, nil, nil, err
	}

	return pkScript, witnessScript, nil, nil
}

func buildSecondLevelScripts(chanState *channeldb.OpenChannel,
	keyRing *lnwallet.CommitmentKeyRing, csvDelay, leaseExpiry uint32) (
	[]byte, []byte, []byte, error) {

	var auxLeaf input.AuxTapLeaf
	scriptInfo, err := lnwallet.SecondLevelHtlcScript(
		chanState.ChanType, chanState.IsInitiator,
		keyRing.RevocationKey, keyRing.ToLocalKey, csvDelay,
		leaseExpiry, auxLeaf,
	)
	if err != nil {
		return nil, nil, nil, err
	}

	witnessScript, err := scriptInfo.WitnessScriptForPath(
		input.ScriptPathSuccess,
	)
	if err != nil {
		return nil, nil, nil, err
	}

	var ctrlBytes []byte
	if tapDesc, ok := scriptInfo.(input.TapscriptDescriptor); ok {
		ctrl, err := tapDesc.CtrlBlockForPath(
			input.ScriptPathSuccess,
		)
		if err != nil {
			return nil, nil, nil, err
		}
		ctrlBytes, err = ctrl.ToBytes()
		if err != nil {
			return nil, nil, nil, err
		}
	}

	return scriptInfo.PkScript(), witnessScript, ctrlBytes, nil
}

func sighashName(sigHash txscript.SigHashType) string {
	switch sigHash {
	case txscript.SigHashAll:
		return "all"
	case txscript.SigHashSingle:
		return "single"
	case txscript.SigHashSingle | txscript.SigHashAnyOneCanPay:
		return "single_anyonecanpay"
	case txscript.SigHashAll | txscript.SigHashAnyOneCanPay:
		return "all_anyonecanpay"
	case txscript.SigHashDefault:
		return "default"
	default:
		return "custom"
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
