test -z "$ETH_RPC_URL" && echo Please set ETH_RPC_URL before running this program && exit 1
NETWORK=${NETWORK:-"--network=local"}
for i in `seq 3 -1 0` ; do echo -ne "\rAbout to run with $NETWORK, CTRL-C now if it is not what your want.. ($i) " ; sleep 1 ; done
echo
echo Calling set_icp_config...
CKICP_CANISTER_ID=$(dfx canister $NETWORK id minter)
ETHRPC_CANISTER_ID=$(dfx canister $NETWORK id ethrpc)
CKICP_ETH_ADDRESS="vec {0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;}"
ICP_LEDGER_CANISTER_ID=$(dfx canister $NETWORK id ledger)
dfx canister $NETWORK call minter set_ckicp_config "(record {
  expiry_seconds = 18000: nat64;
  max_response_bytes = 4000: nat64;
  target_chain_ids = vec {1}: vec nat8;
  ckicp_eth_erc20_address = \"0x8c283B98Edeb405816FD1D321005dF4d3AA956ba\";
  eth_rpc_service_url = \"$ETH_RPC_URL\";
  ckicp_canister_id = principal \"$CKICP_CANISTER_ID\";
  eth_rpc_canister_id = principal \"$ETHRPC_CANISTER_ID\";
  ckicp_eth_address = $CKICP_ETH_ADDRESS : vec nat8;
  ledger_canister_id = principal \"$ICP_LEDGER_CANISTER_ID\";
  ckicp_getlogs_topics = vec { \"0xa6a16062bb41b9bcfb300790709ad9b778bcb5cdcf87dfa633ab3adfd8a7ab59\"; \"0x7fe818d2b919ac5cc197458482fab0d4285d783795541be06864b0baa6ac2f5c\" } : vec text;
  ckicp_fee = 10000 : nat64;
  starting_block_number = 0 : nat64;
  cycle_cost_of_eth_getlogs = 900000000 : nat;
  cycle_cost_of_eth_blocknumber = 900000000 : nat;
})"
echo Calling update_ckicp_state...
dfx canister $NETWORK call minter update_ckicp_state
