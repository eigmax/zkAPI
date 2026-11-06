#!/usr/bin/env bash
# Read-only checks of what zkAPI's contracts and services need from a chain.
# Usage: deploy/preflight.sh RPC_URL [RPC_URL ...]
set -u
rpc() {
  curl -s -m 20 -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":$3}" "$1"
}
ok() { if [ "$1" = "$2" ]; then echo yes; else echo "no ($3)"; fi; }
ONE=0x0000000000000000000000000000000000000000000000000000000000000001
for U in "$@"; do
  echo "== $U"
  echo "chain id:          $(rpc "$U" eth_chainId '[]' | sed -n 's/.*"result":"\(0x[0-9a-f]*\)".*/\1/p' | xargs printf '%d\n' 2>/dev/null)"
  fin=$(rpc "$U" eth_getBlockByNumber '["finalized",false]')
  echo "finalized tag:     $(echo "$fin" | grep -q '"hash"' && echo yes || echo no)"
  echo "EIP-1559 base fee: $(rpc "$U" eth_getBlockByNumber '["latest",false]' | grep -q baseFeePerGas && echo yes || echo no)"
  r=$(rpc "$U" eth_call '[{"data":"0x600160005d60005c60005260206000f3"},"latest"]')
  echo "TSTORE/TLOAD:      $(ok "$(echo "$r" | sed -n 's/.*"result":"\([^"]*\)".*/\1/p')" $ONE reverts)"
  r=$(rpc "$U" eth_call '[{"data":"0x60016000526020600060205e60206020f3"},"latest"]')
  echo "MCOPY:             $(ok "$(echo "$r" | sed -n 's/.*"result":"\([^"]*\)".*/\1/p')" $ONE reverts)"
  r=$(rpc "$U" eth_call '[{"data":"0x60015f5260205ff3"},"latest"]')
  echo "PUSH0:             $(ok "$(echo "$r" | sed -n 's/.*"result":"\([^"]*\)".*/\1/p')" $ONE reverts)"
  r=$(rpc "$U" eth_call '[{"to":"0x0000000000000000000000000000000000000008","data":"0x"},"latest"]')
  echo "BN254 pairing:     $(ok "$(echo "$r" | sed -n 's/.*"result":"\([^"]*\)".*/\1/p')" $ONE missing)"
  code() { rpc "$U" eth_getCode "[\"$1\",\"latest\"]" | sed -n 's/.*"result":"\(0x[0-9a-f]*\)".*/\1/p'; }
  c=$(code 0x0000000071727De22E5E9d8BAf0edAc6f37da032)
  echo "EntryPoint v0.7:   $([ ${#c} -gt 2 ] && echo yes || echo no)"
  c=$(code 0x4e59b44847b379578588920ca78fbf26c0b4956c)
  echo "CREATE2 deployer:  $([ ${#c} -gt 2 ] && echo yes || echo no)"
done
