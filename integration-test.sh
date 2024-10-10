#!/bin/sh

# Running this "test" on a testnet is expected to return errors in the logs:
# "unable to handle swap unable to create order via CoW API" / invalid sig.
# This is because the order hash on testnets and on mainnet are different since
# mainnet data (like the domain separator) is hardcoded on Milkman.
# The way to see in the logs that things are somewhat working as expected in a
# testnet is searching for the string "Is valid sig? true" (and not false).

export INFURA_API_KEY=e74132f416d346308763252779d7df22
export RUST_LOG=DEBUG

# Test values on Sepolia. Everything was manually deployed and an order was
# manually created before running this test.
export MILKMAN_ADDRESS=0x127da72fd5b1f5b63c07ca7042fd2291ff266f0f
export MILKMAN_NETWORK=sepolia
export HASH_HELPER_ADDRESS=0xedEC434fe93E23772C669E2a3252B22Ef6E05049
export STARTING_BLOCK_NUMBER=6849284

# Comment out test values on Sepolia and uncomment entries below to run on
# mainnet.
# Beware: if running this test on mainnet, it's actually going to make order
# creation requests to the API for each identified order.
#export MILKMAN_NETWORK=mainnet
#export STARTING_BLOCK_NUMBER=20927150

cargo run
