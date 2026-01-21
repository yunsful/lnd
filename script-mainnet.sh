#!/usr/bin/env bash
set -euo pipefail

NET="mainnet"           # mainnet/testnet/regtest
LNCLI="./lncli-debug --network=${NET}"
ADDR_TYPE="p2tr"       # p2wkh or p2tr (지갑이 지원하는 타입)
FEE_RATE=1              # sat/vbyte
RBF_SEQUENCE=0 # 0xFFFFFFFD
PARENT_AMT=1500       # 부모 출력 값 (sat)
CHILD_AMT=1000        # 자식 전송 값 (sat) — 부모 출력보다 작게
MIN_CONFS=0             # 부모 입력 펀딩 시 최소 컨펌(미확정도 허용하려면 0)
REPLACE_FEE_SAT=1000        # replace tx 절대 수수료(sat). 0이면 REPLACE_FEE_RATE 사용
REPLACE_FEE_RATE=7       # fallback sat/vbyte


RPCSERVER="127.0.0.1:10009"
TLSCERT="$HOME/Library/Application Support/Lnd/tls.cert"
MACAROON="$HOME/Library/Application Support/Lnd/data/chain/bitcoin/mainnet/admin.macaroon"

HTLC_OUTPOINT="6247c37b62a3ceeab4b5df65a9eb92f89eeaa8d91eba8bd716b191e342232d1c:3"
HTLC_VALUE_SAT=3000
HTLC_PK_SCRIPT="0020ce7f9105ad24b390917c35a74d69fcad267ca28dead7cc3ba9b771fc5c9e1361"
HTLC_WITNESS_SCRIPT="76a914f52184b89f0c28d25506b4957a44aa197125ed918763ac672102b365d0a4ffffabe8f68ff090806c040def4fb41e8df744cda841411d6ee700ea7c820120876475527c2103d9b1f56c896713eae895e2cde27ed19240164526f896815b62dfb37c7c45232152ae67a914cf05668d34a4fad15127c6a48924be64f44ff94e88ac6851b27568"
PREIMAGE="bb3867167366b43a0d1cbba79a7c7e69fcf9c591c5a4c8ca59eab769e6afb9f5"
SINGLE_TWEAK="a853dc87617575294df9fa99a0e50a2c5acfd1d72e53dcb7b187cc89ea051f2b"
KEY_FAMILY=2
KEY_INDEX=26
SAT_PER_VBYTE=1

SWEEP_ADDR="bc1qkfjemmd5ehcr8ht5lzpfm8sec8k3kgpzmxeuqx" #메인넷 수정 필수
FEE_OVERRIDE=800 # maybe 수정
OUT_FILE="/Users/kim/GolandProjects/lnd/tmp/htlc_sweep.out"

echo "[1/12] 부모 수신 주소 생성"
PARENT_ADDR=$(${LNCLI} newaddress ${ADDR_TYPE} | jq -r .address)
echo "부모 주소: ${PARENT_ADDR}"

# 잔액 확인 후 부족하면 중단
BAL=$(${LNCLI} walletbalance)
BAL_CONF=$(echo "${BAL}" | jq -r .confirmed_balance)
BAL_UNCONF=$(echo "${BAL}" | jq -r .unconfirmed_balance)
BAL_TOTAL=$((BAL_CONF + BAL_UNCONF))
REQ=$((PARENT_AMT + 2000))
if [ "${BAL_TOTAL}" -lt "${REQ}" ]; then
  echo "잔액 부족: 필요>=${REQ}sat, 보유=${BAL_TOTAL}sat (conf=${BAL_CONF}, unconf=${BAL_UNCONF})" >&2
  exit 1
fi

echo "[2/12] 부모 PSBT 펀딩 (전파 안 함)"
PARENT_OUTPUTS=$(jq -nc --arg addr "${PARENT_ADDR}" --argjson amt ${PARENT_AMT} '{($addr):$amt}')
echo "부모 outputs JSON: ${PARENT_OUTPUTS}"
PARENT_FUND_RAW=$(${LNCLI} wallet psbt fund --outputs="${PARENT_OUTPUTS}" --sat_per_vbyte=${FEE_RATE} --min_confs=${MIN_CONFS})
PARENT_FUND=$(echo "${PARENT_FUND_RAW}" | jq -e . >/dev/null 2>&1 && echo "${PARENT_FUND_RAW}")
PARENT_PSBT=$(echo "${PARENT_FUND}" | jq -r '.funded_psbt // .psbt')
if [ -z "${PARENT_PSBT}" ] || [ "${PARENT_PSBT}" = "null" ]; then
  echo "fund 부모 PSBT 실패: ${PARENT_FUND_RAW}" >&2
  exit 1
fi
PARENT_PSBT=$(go run ./cmd/psbtseq --psbt "${PARENT_PSBT}" --sequence "${RBF_SEQUENCE}")
PARENT_CHANGE_IDX=$(echo "${PARENT_FUND}" | jq -r '.change_output_index // -1')
PARENT_INPUTS=$(bitcoin-cli decodepsbt "${PARENT_PSBT}" | jq '[.tx.vin[] | "\(.txid):\(.vout)"]')
if [ -z "${PARENT_INPUTS}" ] || [ "${PARENT_INPUTS}" = "[]" ]; then
  echo "부모 PSBT에서 입력 추출 실패" >&2
  exit 1
fi
echo "부모 입력: ${PARENT_INPUTS}"

PARENT_FINAL=$(${LNCLI} wallet psbt finalize "${PARENT_PSBT}")
PARENT_RAW=$(echo "${PARENT_FINAL}" | jq -r '.hex // .final_tx // .raw_final_tx // empty')

if [ -z "${PARENT_RAW}" ] || [ "${PARENT_RAW}" = "null" ]; then
  PARENT_RAW=$(bitcoin-cli finalizepsbt "${PARENT_PSBT}" | jq -r '.hex // empty')
fi
if [ -z "${PARENT_RAW}" ] || [ "${PARENT_RAW}" = "null" ]; then
  echo "부모 finalize 실패: ${PARENT_FINAL}" >&2
  exit 1
fi
echo "부모 RAW: ${PARENT_RAW}"

PARENT_VSIZE=$(bitcoin-cli decoderawtransaction "${PARENT_RAW}" | jq -r '.vsize // empty')
if [ -z "${PARENT_VSIZE}" ] || [ "${PARENT_VSIZE}" = "0" ]; then
  echo "부모 vsize 추출 실패" >&2
  exit 1
fi
if [ "${REPLACE_FEE_SAT}" -gt 0 ]; then
  REPLACE_FEE_RATE=$(( (REPLACE_FEE_SAT + PARENT_VSIZE - 1) / PARENT_VSIZE ))
  REPLACE_FEE_ACTUAL=$(( REPLACE_FEE_RATE * PARENT_VSIZE ))
  echo "대체 수수료(절대값): ${REPLACE_FEE_SAT}sat -> ${REPLACE_FEE_RATE}sat/vB (vsize=${PARENT_VSIZE}, 실제=${REPLACE_FEE_ACTUAL}sat)"
fi

# 첫 번째 fund가 입력을 잠가버리기 때문에, 같은 입력으로 REPLACE를 펀딩하려면
# 잠금을 해제한 뒤 다시 fund 해야 한다.
echo "부모 입력 잠금 해제 (replace 펀딩용)"
echo "${PARENT_INPUTS}" | jq -r '.[]' | while read -r op; do
  ${LNCLI} wallet releaseoutput "${op}" || true
done

# 동일 입력으로 대체 수수료용 PSBT 작성
REPLACE_FUND_RAW=$(${LNCLI} wallet psbt fund --outputs="${PARENT_OUTPUTS}" --inputs="${PARENT_INPUTS}" --sat_per_vbyte=${REPLACE_FEE_RATE} --min_confs=${MIN_CONFS})
REPLACE_FUND=$(echo "${REPLACE_FUND_RAW}" | jq -e . >/dev/null 2>&1 && echo "${REPLACE_FUND_RAW}")
REPLACE_PSBT=$(echo "${REPLACE_FUND}" | jq -r '.funded_psbt // .psbt')
if [ -z "${REPLACE_PSBT}" ] || [ "${REPLACE_PSBT}" = "null" ]; then
  echo "fund 대체 PSBT 실패: ${REPLACE_FUND_RAW}" >&2
  exit 1
fi
REPLACE_PSBT=$(go run ./cmd/psbtseq --psbt "${REPLACE_PSBT}" --sequence "${RBF_SEQUENCE}")

REPLACE_FINAL=$(${LNCLI} wallet psbt finalize "${REPLACE_PSBT}")
REPLACE_RAW=$(echo "${REPLACE_FINAL}" | jq -r '.hex // .final_tx // .raw_final_tx // empty')
echo "부모 대체 RAW: ${REPLACE_RAW}"

PARENT_DECODE=$(bitcoin-cli decoderawtransaction "${PARENT_RAW}")
PARENT_TXID=$(echo "${PARENT_DECODE}" | jq -r '.txid')
PARENT_VOUT=$(echo "${PARENT_DECODE}" | jq -r --arg addr "${PARENT_ADDR}" '.vout[] | select(.scriptPubKey.address==$addr).n')
if [ -z "${PARENT_VOUT}" ]; then
  # fallback: target이 change일 수 있으니 change_output_index 외의 vout 선택
  PARENT_VOUT=$(echo "${PARENT_DECODE}" | jq -r --argjson chg "${PARENT_CHANGE_IDX}" '.vout[] | select(.n != $chg).n' | head -n1)
fi
ADD_PK_SCRIPT=$(echo "${PARENT_DECODE}" | jq -r --argjson idx "${PARENT_VOUT}" '.vout[] | select(.n==$idx).scriptPubKey.hex')
echo "부모 TXID: ${PARENT_TXID}, vout: ${PARENT_VOUT}"


USE_EXTRA_INPUT=true
OP_RETURN_DATA="7dcde323076181d348248e5943a7bf550229419e62ab0c9115b37ab0e86750ee1e387e07e2e6f42dcf0f5a101010" # "7dcde323076181d348248e5943a7bf550229419e62ab0c9115b37ab0e86750ee1e387e07e2e6f42dcf0f5a101010"
ADD_TXID=${PARENT_TXID} # 수정필수
ADD_VOUT=${PARENT_VOUT} # 수정필수
ADD_VALUE_SAT=${PARENT_AMT} # 수정필수
ADD_SEQUENCE=${RBF_SEQUENCE}

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
echo "[3/12] HTLC 입력 서명 완료, raw tx: $RAW_TX"
if [ -n "${OP_RETURN_DATA}" ]; then
  if ! bitcoin-cli decoderawtransaction "$RAW_TX" | jq -e '.vout[] | select(.scriptPubKey.type=="nulldata")' >/dev/null; then
    echo "ERROR: OP_RETURN output missing in raw tx" >&2
    exit 1
  fi
  echo "[3.2/12] OP_RETURN 확인 완료"
fi

if [ "${USE_EXTRA_INPUT}" = "true" ]; then
  # HTLC 입력은 이미 최종 서명되었으므로 PSBT에 final witness로 고정하고,
  # 지갑 UTXO(witness_utxo 포함)만 lnd가 서명하도록 만든다.
  echo "[3.5/12] 부모 전파"
  PARENT_BROADCAST=$(bitcoin-cli sendrawtransaction "${PARENT_RAW}")
  echo "부모 TXID (전파됨): ${PARENT_BROADCAST}"

  sleep 2

  PSBT_BASE64=$(go run ./cmd/htlcpsbt \
    --raw_tx="${RAW_TX}" \
    --htlc_value_sat="${HTLC_VALUE_SAT}" \
    --htlc_pk_script="${HTLC_PK_SCRIPT}" \
    --utxo_value_sat="${ADD_VALUE_SAT}" \
    --utxo_pk_script="${ADD_PK_SCRIPT}")
  echo "[4/12] PSBT 생성 완료" 

  FINALIZE=$(./lncli-debug --network=${NET} wallet psbt finalize "$PSBT_BASE64")
  FINAL_HEX=$(echo "$FINALIZE" | jq -r .final_tx)
  echo "[5/12] 추가 입력 서명 완료"

  # HTLC 위트니스를 원본(raw)에서 유지한 채 병합
  MERGED_HEX=$(go run ./cmd/htlcmerge \
    --raw_tx="${RAW_TX}" \
    --final_tx="${FINAL_HEX}" \
    --htlc_input_index=0)
  echo "[6/12] HTLC 위트니스 병합 완료"
  echo "[6.5/12] 머지 완료: $MERGED_HEX"
  echo "[7/12] 자식 수신 주소 생성"
  CHILD_ADDR=$(${LNCLI} newaddress ${ADDR_TYPE} | jq -r .address)
  echo "자식 주소: ${CHILD_ADDR}"

  echo "[9/12] 자식 PSBT 펀딩 (부모 출력 소비)"
  CHILD_OUTPUTS=$(jq -nc --arg addr "${CHILD_ADDR}" --argjson amt ${CHILD_AMT} '{($addr):$amt}')
  echo "자식 outputs JSON: ${CHILD_OUTPUTS}"
  CHILD_INPUTS=$(jq -nc --arg inp "${PARENT_TXID}:${PARENT_VOUT}" '[ $inp ]')
  CHILD_FUND_RAW=$(${LNCLI} wallet psbt fund --outputs="${CHILD_OUTPUTS}" --inputs="${CHILD_INPUTS}" --sat_per_vbyte=${FEE_RATE} --min_confs=0)
  CHILD_FUND=$(echo "${CHILD_FUND_RAW}" | jq -e . >/dev/null 2>&1 && echo "${CHILD_FUND_RAW}")
  CHILD_PSBT=$(echo "${CHILD_FUND}" | jq -r '.funded_psbt // .psbt')
  if [ -z "${CHILD_PSBT}" ] || [ "${CHILD_PSBT}" = "null" ]; then
    echo "fund 자식 PSBT 실패: ${CHILD_FUND_RAW}" >&2
    exit 1
  fi
  CHILD_PSBT=$(go run ./cmd/psbtseq --psbt "${CHILD_PSBT}" --sequence "${RBF_SEQUENCE}")

  CHILD_FINAL=$(${LNCLI} wallet psbt finalize "${CHILD_PSBT}")
  CHILD_RAW=$(echo "${CHILD_FINAL}" | jq -r '.hex // .final_tx // .raw_final_tx // empty')
  if [ -z "${CHILD_RAW}" ] || [ "${CHILD_RAW}" = "null" ]; then
    CHILD_RAW=$(bitcoin-cli finalizepsbt "${CHILD_PSBT}" | jq -r '.hex // empty')
  fi
  if [ -z "${CHILD_RAW}" ] || [ "${CHILD_RAW}" = "null" ]; then
    echo "자식 finalize 실패: ${CHILD_FINAL}" >&2
    exit 1
  fi
  CHILD_TXID=$(bitcoin-cli decoderawtransaction "${CHILD_RAW}" | jq -r '.txid')

  echo "[10/12] 부모 자식 브로드캐스트/결과"
  echo "부모 RAW:  ${PARENT_RAW}"
  echo "자식 RAW:  ${CHILD_RAW}"
  echo "부모 TXID: ${PARENT_BROADCAST}"
  bitcoin-cli submitpackage "[\"${PARENT_RAW}\",\"${CHILD_RAW}\"]"
  CHILD_BROADCAST=$(bitcoin-cli sendrawtransaction "${CHILD_RAW}")
  echo "자식 TXID: ${CHILD_BROADCAST}"

  # sleep 30

  # # 브로드캐스트
  # TXID=$(bitcoin-cli sendrawtransaction "$MERGED_HEX")
  # echo "[11/12] preimage 브로드캐스트 완료: $TXID"

  # sleep 

  # REPLACE_BROADCAST=$(bitcoin-cli sendrawtransaction "$REPLACE_RAW")
  # echo "[12/12] replace 브로드캐스트 완료: $REPLACE_BROADCAST"

else
  # 추가 입력 없이 HTLC만 있을 때는 raw 바로 사용
  #TXID=$(bitcoin-cli -regtest sendrawtransaction "$RAW_TX")
  echo "[2/2] 브로드캐스트 완료: $RAW_TX"
fi
