#!/usr/bin/env bash
set -euo pipefail

NET="regtest"           # mainnet/testnet/regtest
LNCLI="./lncli-debug --network=${NET}"
ADDR_TYPE="p2tr"       # p2wkh or p2tr (지갑이 지원하는 타입)
FEE_RATE=1              # sat/vbyte
PARENT_AMT=1500       # 부모 출력 값 (sat)
CHILD_AMT=1000        # 자식 전송 값 (sat) — 부모 출력보다 작게
MIN_CONFS=0             # 부모 입력 펀딩 시 최소 컨펌(미확정도 허용하려면 0)
REPLACE_FEE_RATE=5

echo "[1/6] 부모 수신 주소 생성"
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

echo "[2/6] 부모 PSBT 펀딩 (전파 안 함)"
PARENT_OUTPUTS=$(jq -nc --arg addr "${PARENT_ADDR}" --argjson amt ${PARENT_AMT} '{($addr):$amt}')
echo "부모 outputs JSON: ${PARENT_OUTPUTS}"
PARENT_FUND_RAW=$(${LNCLI} wallet psbt fund --outputs="${PARENT_OUTPUTS}" --sat_per_vbyte=${FEE_RATE} --min_confs=${MIN_CONFS})
PARENT_FUND=$(echo "${PARENT_FUND_RAW}" | jq -e . >/dev/null 2>&1 && echo "${PARENT_FUND_RAW}")
PARENT_PSBT=$(echo "${PARENT_FUND}" | jq -r '.funded_psbt // .psbt')
if [ -z "${PARENT_PSBT}" ] || [ "${PARENT_PSBT}" = "null" ]; then
  echo "fund 부모 PSBT 실패: ${PARENT_FUND_RAW}" >&2
  exit 1
fi
PARENT_CHANGE_IDX=$(echo "${PARENT_FUND}" | jq -r '.change_output_index // -1')
PARENT_INPUTS=$(bitcoin-cli decodepsbt "${PARENT_PSBT}" | jq '[.tx.vin[] | "\(.txid):\(.vout)"]')
if [ -z "${PARENT_INPUTS}" ] || [ "${PARENT_INPUTS}" = "[]" ]; then
  echo "부모 PSBT에서 입력 추출 실패" >&2
  exit 1
fi
echo "부모 입력: ${PARENT_INPUTS}"

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

PARENT_FINAL=$(${LNCLI} wallet psbt finalize "${PARENT_PSBT}")
REPLACE_FINAL=$(${LNCLI} wallet psbt finalize "${REPLACE_PSBT}")
PARENT_RAW=$(echo "${PARENT_FINAL}" | jq -r '.hex // .final_tx // .raw_final_tx // empty')
REPLACE_RAW=$(echo "${REPLACE_FINAL}" | jq -r '.hex // .final_tx // .raw_final_tx // empty')

if [ -z "${PARENT_RAW}" ] || [ "${PARENT_RAW}" = "null" ]; then
  PARENT_RAW=$(bitcoin-cli -${NET} finalizepsbt "${PARENT_PSBT}" | jq -r '.hex // empty')
fi
if [ -z "${PARENT_RAW}" ] || [ "${PARENT_RAW}" = "null" ]; then
  echo "부모 finalize 실패: ${PARENT_FINAL}" >&2
  exit 1
fi
echo "부모 RAW: ${PARENT_RAW}"
echo "부모 대체 RAW: ${REPLACE_RAW}"

PARENT_DECODE=$(bitcoin-cli -${NET} decoderawtransaction "${PARENT_RAW}")
PARENT_TXID=$(echo "${PARENT_DECODE}" | jq -r '.txid')
PARENT_VOUT=$(echo "${PARENT_DECODE}" | jq -r --arg addr "${PARENT_ADDR}" '.vout[] | select(.scriptPubKey.address==$addr).n')
if [ -z "${PARENT_VOUT}" ]; then
  # fallback: target이 change일 수 있으니 change_output_index 외의 vout 선택
  PARENT_VOUT=$(echo "${PARENT_DECODE}" | jq -r --argjson chg "${PARENT_CHANGE_IDX}" '.vout[] | select(.n != $chg).n' | head -n1)
fi
echo "부모 TXID: ${PARENT_TXID}, vout: ${PARENT_VOUT}"

echo "[3/6] 자식 수신 주소 생성"
CHILD_ADDR=$(${LNCLI} newaddress ${ADDR_TYPE} | jq -r .address)
echo "자식 주소: ${CHILD_ADDR}"

echo "[4/6] 부모 전파"
PARENT_BROADCAST=$(bitcoin-cli -${NET} sendrawtransaction "${PARENT_RAW}")
echo "부모 TXID (전파됨): ${PARENT_BROADCAST}"

echo "[5/6] 자식 PSBT 펀딩 (부모 출력 소비)"
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

CHILD_FINAL=$(${LNCLI} wallet psbt finalize "${CHILD_PSBT}")
CHILD_RAW=$(echo "${CHILD_FINAL}" | jq -r '.hex // .final_tx // .raw_final_tx // empty')
if [ -z "${CHILD_RAW}" ] || [ "${CHILD_RAW}" = "null" ]; then
  CHILD_RAW=$(bitcoin-cli -${NET} finalizepsbt "${CHILD_PSBT}" | jq -r '.hex // empty')
fi
if [ -z "${CHILD_RAW}" ] || [ "${CHILD_RAW}" = "null" ]; then
  echo "자식 finalize 실패: ${CHILD_FINAL}" >&2
  exit 1
fi
CHILD_TXID=$(bitcoin-cli -${NET} decoderawtransaction "${CHILD_RAW}" | jq -r '.txid')

echo "[6/6] 브로드캐스트/결과"
echo "부모 RAW:  ${PARENT_RAW}"
echo "자식 RAW:  ${CHILD_RAW}"
echo "부모 TXID: ${PARENT_BROADCAST}"
# CHILD_BROADCAST=$(bitcoin-cli sendrawtransaction "${CHILD_RAW}")
echo "자식 TXID: ${CHILD_BROADCAST}"
