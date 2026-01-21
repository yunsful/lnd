MAC=$(xxd -ps -u -c 1000 ~/Library/Application\ Support/Lnd/data/chain/bitcoin/mainnet/admin.macaroon)

RESP=$(grpcurl \
  -cacert ~/Library/Application\ Support/Lnd/tls.cert \
  -rpc-header "macaroon:$MAC" \
  -import-path lnrpc \
  -proto signrpc/signer.proto \
  -d '{
    "chan_point":{"funding_txid_str":"c2f97f77bd88b559ed11564506edd3e83a6ac9b284dcd01ee7b35eea9fdf5831","output_index":0},
    "htlc_id":0,
    "incoming":true
  }' \
  127.0.0.1:10009 signrpc.Signer/GetHtlcSpendInfo)

echo "$RESP"

RESP="$RESP" python3 - <<'PY'
import base64
import json
import os
import sys

raw = os.environ.get("RESP", "")
if not raw:
    print("htlcPkScriptHex: <missing>")
    print("witnessScriptHex: <missing>")
    print("singleTweakHex: <missing>")
    sys.exit(0)

resp = json.loads(raw)
for key in ("htlcPkScript", "witnessScript", "singleTweak"):
    val = resp.get(key)
    if not val:
        print(f"{key}Hex: <missing>")
        continue
    print(f"{key}Hex: {base64.b64decode(val).hex()}")
PY
