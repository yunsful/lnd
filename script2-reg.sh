MAC=$(xxd -ps -u -c 1000 ~/Library/Application\ Support/Lnd/data/chain/bitcoin/regtest/admin.macaroon)

grpcurl \
  -cacert ~/Library/Application\ Support/Lnd/tls.cert \
  -rpc-header "macaroon:$MAC" \
  -import-path lnrpc \
  -proto signrpc/signer.proto \
  -d '{
    "chan_point":{"funding_txid_str":"211cf6cf302387d259f425a8dfead23635c9b9ccc380b72d4f4d80c41f2058ff","output_index":0},
    "htlc_id":0,
    "incoming":true
  }' \
  127.0.0.1:10009 signrpc.Signer/GetHtlcSpendInfo