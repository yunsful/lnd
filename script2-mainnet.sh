#!/usr/bin/env bash
set -euo pipefail

NET="mainnet"            # mainnet/testnet/regtest
LNCLI="./lncli-debug --network=${NET}"

RPCSERVER="127.0.0.1:10009"
TLSCERT="$HOME/Library/Application Support/Lnd/tls.cert"
MACAROON="$HOME/Library/Application Support/Lnd/data/chain/bitcoin/mainnet/admin.macaroon"

# HTLC outpoint from your local commitment.
HTLC_OUTPOINT="0f80e97c1902a2cff1c4bb640eda7849551364701db9f04f07ebf7cb2f4d5d2e:2"
HTLC_VALUE_SAT=1000
HTLC_PK_SCRIPT="00205e140b023e609e361b7917f2322cd491653bb184f9632a1f246daa464b6e44f3"
HTLC_WITNESS_SCRIPT="76a9144b7dae743b7bfde78d2c4ba42ec1143b0241ed668763ac6721020803199d4c78651d146ceb1c3f4bb1d1c41123913af8dea365f24393e2afdb587c8201208763a9143586e074fd463773f849f2f7755327f54b7484e288527c2103bfa4f1f9f68727adcd717a067771893db81b5c7b175a024b41852d02ddc4278552ae677503383c0eb175ac6851b27568"
CONTROL_BLOCK="" # taproot only

# Sender (remote) signature for the second-level success tx.
SENDER_SIG="3045022100fad6e176c5a8ff6a9e60fadf1c713a907014721f335edccc75274d240c8fafd00220684e692894537c22a1dbf22f3b1aec4f3c37afb51cd6dab3e7355095a0b8df68"

PREIMAGE="a924d12510f7893bd83f59cb3b2e16c337da471dc44a794e6f942e4a557d9c74"
SINGLE_TWEAK="291d696eb10716f67badb6d80c6beb5b09af1d550e4133aa9b5dc8a2cb633fde"
KEY_FAMILY=2
KEY_INDEX=27

# Second-level output (must match the pre-signed output).
SECOND_LEVEL_VALUE_SAT=1000
SECOND_LEVEL_PK_SCRIPT="002025905c1ec23b00885af03af646b48fa5f5ef0138a9df6aaab5a539829173a78d"

# Sighash types: all | single_anyonecanpay | default | 0x..
SIGHASH="single_anyonecanpay"
SENDER_SIGHASH="single_anyonecanpay" # empty = use SIGHASH
TAPROOT=false

# Optional extra inputs/outputs (createrawtransaction-style JSON).
ADD_INPUTS_JSON='[
  { "txid": "09313b56dc4b2ba097d4a0526a93b24488788837ded5cba695e09dff20a1f7c7", "vout": 0, "sequence": 0 },
  { "txid": "591979c6ee3259cee2864c725e768c1a399b7e77ce3628628575bba09c76424e", "vout": 0, "sequence": 0 },
  { "txid": "5507b2fa68100d284c851915de56a1132ad38111d429077e6e0c510f9669748f", "vout": 0, "sequence": 0 },
  { "txid": "51f81191aca743b04041499543c21dddaac51a2a078ff4277cf483cf9a4ef57a", "vout": 0, "sequence": 0 },
  { "txid": "c79e5ec60c5d9700a2a906619c27b38d6873f39d91bf517c02fac52596d8e776", "vout": 0, "sequence": 0 },
  { "txid": "9db1d1788542ab8ace26a72da32fc30892d075885b72178bc26951713a8ad209", "vout": 0, "sequence": 0 }
]'
ADD_OUTPUTS_JSON='[
  {"bc1qghk43swrw97e63pcp60eup6de2fze60q6gd780": "514sat"},
  {"bc1qtt5eq4n5emrp6ek9cw3dzx3ah49qzjrrpr9fm9": "514sat"},
  {"bc1qv0ntl360vftrw4wgwhwnxzsf92e0lhmapxtz9z": "514sat"},
  {"bc1q9gg9v59xsvywyfajruncuaxvu7n3y4p2fs9zrr": "514sat"},
  {"bc1qcphfntwxw69yaxpe520zjgssf360t530tdnuy8": "514sat"},
  {"bc1q5ckury6ealaz3x32f0w2wkqaf9exr4h9n6x2w5": "514sat"},
  {"bc1qqwnklkxnyamlzsgwp4f37ypuayf6t5q77z5fjh": "514sat"},
  {"bc1qujud9man5eeqeflghj8addk7g2nw6svq64txn0": "514sat"},
  {"bc1qj76r7nmgsh6mju3wenxj4srm4kc2j5cj06gq7v": "514sat"},
  {"bc1qgg2vxq9zf5tuys08wtrak8m0dm8h5hpkvg5fpq": "514sat"},
  {"bc1qn2em854hsylg9lpfgd8j23j55ktzkydy6cdzn9": "514sat"}
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
if [ -n "${ADD_OUTPUTS_JSON}" ]; then
  EXTRA_FLAGS+=(--add_outputs_json="${ADD_OUTPUTS_JSON}")
fi

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

  MERGED_HEX=$(go run ./cmd/htlcmerge \
    --raw_tx="${RAW_TX}" \
    --final_tx="${FINAL_HEX}" \
    --htlc_input_index=0)

  echo "Merged transaction: ${MERGED_HEX}"
else
  echo "Raw transaction: ${RAW_TX}"
fi
