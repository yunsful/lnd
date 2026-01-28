#!/usr/bin/env bash
set -euo pipefail

NET="mainnet"            # mainnet/testnet/regtest
LNCLI="./lncli-debug --network=${NET}"

RPCSERVER="127.0.0.1:10009"
TLSCERT="$HOME/Library/Application Support/Lnd/tls.cert"
MACAROON="$HOME/Library/Application Support/Lnd/data/chain/bitcoin/mainnet/admin.macaroon"

# HTLC outpoint from your local commitment.
HTLC_OUTPOINT="24a924fc7216d695a796bbba2b7e42249f2034f5687a48172c31fcb210dcccb9:2"
HTLC_VALUE_SAT=1000
HTLC_PK_SCRIPT="00202ef234adbd54423342dd97744004766594926004135ff1bc0cb464d370661dc4"
HTLC_WITNESS_SCRIPT="76a914a01a27ce487846b48ad6443023762a38698e2fb28763ac672103ba520261c537b5825b5d38b632adc726c31985724b9967d5b3c61bde36e3f9107c8201208763a91422e83fcf32bb801177d0cdd28f48b41b9258842c88527c21035ea9d3f39c96ca89e507b2c95a9fe4c23e57286f0e93135777734448330795e852ae677503763e0eb175ac6851b27568"
CONTROL_BLOCK="" # taproot only

# Sender (remote) signature for the second-level success tx.
SENDER_SIG="304402204caeba74ac2b0184920ff77fecf2469f67e0471f90c2c5ef58a46cecea5523d702204dbecbe8add3047eba9fb4b2895af09ce4401c67f251b401fd9520d07921a8ed"

PREIMAGE="275559c077f2563c42c4d173648b7fdb42843f3e48dcaad6db1b49d8002a6f14"
SINGLE_TWEAK="31f1a52fa2bb3da86a76cc42d9c78f49b687acd4cbc7969475d7c6fd386ff1e3"
KEY_FAMILY=2
KEY_INDEX=30

# Second-level output (must match the pre-signed output).
SECOND_LEVEL_VALUE_SAT=1000
SECOND_LEVEL_PK_SCRIPT="0020c5337bd03f31e195bac0486807f30c6bdbc1fcadffa20d3fc9f449e6ae9e413f"

# Sighash types: all | single_anyonecanpay | default | 0x..
SIGHASH="single_anyonecanpay"
SENDER_SIGHASH="single_anyonecanpay" # empty = use SIGHASH
TAPROOT=false

# Optional extra inputs/outputs (createrawtransaction-style JSON).
ADD_INPUTS_JSON='[
  {"txid":"732b09773d85959010b694bf9c2e2ace2762374090fb328affff764d4b09e2c2","vout":0,"sequence":0}
]'
ADD_INPUTS=(
  # "txid:vout:value:sequence"
  # "732b09773d85959010b694bf9c2e2ace2762374090fb328affff764d4b09e2c2:0:1500:0"
)
ADD_INPUT_WITNESSES=(
  # "1:<tapscript_hex>,<control_block_hex>"
)
MERGE_PRESERVE_INPUTS=()
ADD_OUTPUTS_JSON='[
  {"bc1pcxrgsjz20n4tv7smpp55lkf0hcccjusaz90k2zupp840z840l56qz8nzvm":0.00001000},
  {"data": "7dcde323076181d348248e5943a7bf550229419e62ab0c9115b37ab0e86750ee1e387e07e2e6f42dcf0f5a101010"}
]'

OUT_FILE="/Users/kim/GolandProjects/lnd/tmp/htlc_success_2nd.out"

EXTRA_FLAGS=()
HAS_EXTRA_INPUTS=false
if [ -n "${ADD_INPUTS_JSON}" ]; then
  ADD_INPUTS_JSON_MIN=$(echo "${ADD_INPUTS_JSON}" | tr -d '[:space:]')
  if [ "${ADD_INPUTS_JSON_MIN}" != "[]" ]; then
    EXTRA_FLAGS+=(--add_inputs_json="${ADD_INPUTS_JSON}")
    HAS_EXTRA_INPUTS=true
  fi
fi
for input in "${ADD_INPUTS[@]+"${ADD_INPUTS[@]}"}"; do
  EXTRA_FLAGS+=(--add_input="${input}")
  HAS_EXTRA_INPUTS=true
done
if [ -n "${ADD_OUTPUTS_JSON}" ]; then
  EXTRA_FLAGS+=(--add_outputs_json="${ADD_OUTPUTS_JSON}")
fi

EXTRA_WITNESS_FLAGS=()
for witness in "${ADD_INPUT_WITNESSES[@]+"${ADD_INPUT_WITNESSES[@]}"}"; do
  EXTRA_WITNESS_FLAGS+=(--add_input_witness="${witness}")
done

SENDER_SIGHASH_FLAG=()
if [ -n "${SENDER_SIGHASH}" ]; then
  SENDER_SIGHASH_FLAG+=(--sender_sighash="${SENDER_SIGHASH}")
fi

TAPROOT_FLAG=()
if [ "${TAPROOT}" = "true" ]; then
  TAPROOT_FLAG+=(--taproot --control_block="${CONTROL_BLOCK}")
fi

go run ./cmd/htlcsuccess2 \
  --rpcserver="${RPCSERVER}" \
  --tlscert="${TLSCERT}" \
  --macaroon="${MACAROON}" \
  --network="${NET}" \
  --outpoint="${HTLC_OUTPOINT}" \
  --output_value_sat="${HTLC_VALUE_SAT}" \
  --htlc_pk_script="${HTLC_PK_SCRIPT}" \
  --witness_script="${HTLC_WITNESS_SCRIPT}" \
  --preimage="${PREIMAGE}" \
  --sender_sig="${SENDER_SIG}" \
  --sighash="${SIGHASH}" \
  --second_level_pk_script="${SECOND_LEVEL_PK_SCRIPT}" \
  --second_level_value_sat="${SECOND_LEVEL_VALUE_SAT}" \
  --single_tweak="${SINGLE_TWEAK}" \
  --key_family="${KEY_FAMILY}" \
  --key_index="${KEY_INDEX}" \
  ${SENDER_SIGHASH_FLAG[@]+"${SENDER_SIGHASH_FLAG[@]}"} \
  ${TAPROOT_FLAG[@]+"${TAPROOT_FLAG[@]}"} \
  ${EXTRA_FLAGS[@]+"${EXTRA_FLAGS[@]}"} \
  ${EXTRA_WITNESS_FLAGS[@]+"${EXTRA_WITNESS_FLAGS[@]}"} \
  | tee "${OUT_FILE}"

RAW_TX=$(awk '/Raw transaction/ {print $3}' "${OUT_FILE}")
if [ -z "${RAW_TX}" ]; then
  echo "RAW_TX not found" >&2
  exit 1
fi

if [ "${HAS_EXTRA_INPUTS}" = "true" ]; then
  PSBT_ARGS=(
    --raw_tx="${RAW_TX}"
    --htlc_value_sat="${HTLC_VALUE_SAT}"
    --htlc_pk_script="${HTLC_PK_SCRIPT}"
    --rpcserver="${RPCSERVER}"
    --tlscert="${TLSCERT}"
    --macaroon="${MACAROON}"
  )

  PSBT_BASE64=$(go run ./cmd/htlcpsbt "${PSBT_ARGS[@]}")

  FINALIZE=$(${LNCLI} wallet psbt finalize "${PSBT_BASE64}")
  FINAL_HEX=$(echo "${FINALIZE}" | jq -r .final_tx)

  MERGE_FLAGS=()
  for idx in "${MERGE_PRESERVE_INPUTS[@]+"${MERGE_PRESERVE_INPUTS[@]}"}"; do
    MERGE_FLAGS+=(--preserve_input_index="${idx}")
  done

  MERGED_HEX=$(go run ./cmd/htlcmerge \
    --raw_tx="${RAW_TX}" \
    --final_tx="${FINAL_HEX}" \
    --htlc_input_index=0 \
    ${MERGE_FLAGS[@]+"${MERGE_FLAGS[@]}"})

  echo "Merged transaction: ${MERGED_HEX}"
else
  echo "Raw transaction: ${RAW_TX}"
fi
