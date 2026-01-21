#!/usr/bin/env bash
set -euo pipefail

RPCSERVER="127.0.0.1:10009"
TLSCERT="$HOME/Library/Application Support/Lnd/tls.cert"
MACAROON="$HOME/Library/Application Support/Lnd/data/chain/bitcoin/mainnet/admin.macaroon"

RPCSERVER="127.0.0.1:10009"
TLSCERT="$HOME/Library/Application Support/Lnd/tls.cert"
MACAROON="$HOME/Library/Application Support/Lnd/data/chain/bitcoin/mainnet/admin.macaroon"

HTLC_OUTPOINT="65dfc010e75f801f1eec50a2befb89a1b22b0bdbf52f1882562b6a560849dbc2:3"
HTLC_VALUE_SAT=3000
HTLC_PK_SCRIPT="0020e0b86f26c328e313f0d70387d9685813f397aa9a71ae2effc02915e1e850b01a"
HTLC_WITNESS_SCRIPT="76a91456bd8a9f63b72000bfa368dff00ee16ef08e83c88763ac6721039b94951d76ca63332b086b3579d6a77f2390f0144d6c28f41143aafa3ac7da077c820120876475527c210360eb02af5f1323bdce40c126d6098d95b1e698110356be1ea69e21dc21b02b2152ae67a91484353aa3e29e98be8b13891cae559d85aee0740a88ac6851b27568"
PREIMAGE="47d0932d8d264aecf08acf62aa272f2594baa5487faffc672d28817e760d10ae"
SINGLE_TWEAK="dfd389d529df953d909caf693dbe5484e46b9a0f97fdd8f2b79044a69a0c2d37"
KEY_FAMILY=2
KEY_INDEX=23
SAT_PER_VBYTE=1

USE_EXTRA_INPUT=true
OP_RETURN_DATA="" # "7dcde323076181d348248e5943a7bf550229419e62ab0c9115b37ab0e86750ee1e387e07e2e6f42dcf0f5a101010"
ADD_TXID="c4b9136251e1036e76458115803cfccc849964a09cdf70b0c56c2eec6b1d925d" # 수정필수
ADD_VOUT=1 # 수정필수
ADD_VALUE_SAT=1500 # 수정필수
ADD_PK_SCRIPT="51201b26d2b77f9fd27a4d606007bef18a577fbcc38cab64269fcb6b056e26d24a5a" # 수정필수
ADD_SEQUENCE=4294967295

SWEEP_ADDR="bc1ptasu62n2sgfj7ps8ktalrhk3z84v5p8z5t40ykkh53pw5lsdg4kqcge4zq"
FEE_OVERRIDE=700 # maybe 수정
OUT_FILE="/Users/kim/GolandProjects/lnd/tmp/htlc_sweep.out"

EXTRA_FLAGS=()
if [ "${USE_EXTRA_INPUT}" = "true" ]; then
  EXTRA_FLAGS+=(--fee_override_sat="${FEE_OVERRIDE}")
  EXTRA_FLAGS+=(--add_input="${ADD_TXID}:${ADD_VOUT}:${ADD_VALUE_SAT}:${ADD_SEQUENCE}")
fi
if [ -n "${OP_RETURN_DATA}" ]; then
  EXTRA_FLAGS+=(--add_op_return="${OP_RETURN_DATA}")
fi

go run ./cmd/htlcsuccess \
  --rpcserver="${RPCSERVER}" \
  --tlscert="${TLSCERT}" \
  --macaroon="${MACAROON}" \
  --outpoint="${HTLC_OUTPOINT}" \
  --output_value_sat="${HTLC_VALUE_SAT}" \
  --htlc_pk_script="${HTLC_PK_SCRIPT}" \
  --witness_script="${HTLC_WITNESS_SCRIPT}" \
  --preimage="${PREIMAGE}" \
  --single_tweak="${SINGLE_TWEAK}" \
  --key_family="${KEY_FAMILY}" \
  --key_index="${KEY_INDEX}" \
  --sweep_addr="${SWEEP_ADDR}" \
  --sat_per_vbyte="${SAT_PER_VBYTE}" \
  "${EXTRA_FLAGS[@]:-}" \
  | tee "${OUT_FILE}"

RAW_TX=$(awk '/Raw transaction/ {print $3}' "${OUT_FILE}")
if [ -z "${RAW_TX}" ]; then echo "RAW_TX not found"; exit 1; fi
echo "[1/4] HTLC 입력 서명 완료, raw tx: $RAW_TX"
if [ -n "${OP_RETURN_DATA}" ]; then
  if ! bitcoin-cli decoderawtransaction "$RAW_TX" | jq -e '.vout[] | select(.scriptPubKey.type=="nulldata")' >/dev/null; then
    echo "ERROR: OP_RETURN output missing in raw tx" >&2
    exit 1
  fi
  echo "[1.5/4] OP_RETURN 확인 완료"
fi

if [ "${USE_EXTRA_INPUT}" = "true" ]; then
  # HTLC 입력은 이미 최종 서명되었으므로 PSBT에 final witness로 고정하고,
  # 지갑 UTXO(witness_utxo 포함)만 lnd가 서명하도록 만든다.
  PSBT_BASE64=$(go run ./cmd/htlcpsbt \
    --raw_tx="${RAW_TX}" \
    --htlc_value_sat="${HTLC_VALUE_SAT}" \
    --htlc_pk_script="${HTLC_PK_SCRIPT}" \
    --utxo_value_sat="${ADD_VALUE_SAT}" \
    --utxo_pk_script="${ADD_PK_SCRIPT}")
  echo "[2/5] PSBT 생성 완료"

  FINALIZE=$(./lncli-debug wallet psbt finalize "$PSBT_BASE64")
  FINAL_HEX=$(echo "$FINALIZE" | jq -r .final_tx)
  echo "[3/5] 추가 입력 서명 완료"

  # HTLC 위트니스를 원본(raw)에서 유지한 채 병합
  MERGED_HEX=$(go run ./cmd/htlcmerge \
    --raw_tx="${RAW_TX}" \
    --final_tx="${FINAL_HEX}" \
    --htlc_input_index=0)
  echo "[4/5] HTLC 위트니스 병합 완료"

  # 브로드캐스트
  #TXID=$(bitcoin-cli -regtest sendrawtransaction "$MERGED_HEX")
  echo "[5/5] 브로드캐스트 완료: $MERGED_HEX"
else
  # 추가 입력 없이 HTLC만 있을 때는 raw 바로 사용
  #TXID=$(bitcoin-cli -regtest sendrawtransaction "$RAW_TX")
  echo "[2/2] 브로드캐스트 완료: $RAW_TX"
fi
