# Hello World contract deploy on Axelar:

#### Build contract
`cargo wasm` - this builds an unoptimized wasm version of the contract in `target/wasm32-unknown-unknown/release`

`RUSTFLAGS='-C link-arg=-s' cargo wasm` - produces a smaller binary file by removing unwanted code

However, in order to deploy a contract you should do an optimized compilation:
```
sudo docker run --rm -v "$(pwd)":/code \
    --mount type=volume,source="$(basename "$(pwd)")_cache",target=/code/target \
    --mount type=volume,source=registry_cache,target=/usr/local/cargo/registry \
    cosmwasm/rust-optimizer:0.12.6
```

- the optimised wasm code file will be under `artifacts`


#### Deploy command:
`axelard tx wasm store artifacts/cw_tpl_osmosis.wasm --from test --gas auto --gas-adjustment 5 -y --output json -b block --chain-id devnet-wasm --node=http://devnet.rpc.axelar.dev:26657 --gas-prices 0.1uwasm`

- take `CODE_ID` from `.logs[0].events[-1].attributes[0].value`

#### Init contract:
`INIT='{"count":100}'` - data is JSON in Cosmos

`axelard tx wasm instantiate $CODE_ID "$INIT" --from test --label "my first contract" --gas auto --gas-adjustment 5 -y --output json -b block --chain-id devnet-wasm --node=http://devnet.rpc.axelar.dev:26657 --gas-prices 0.1uwasm --no-admin`

- take txHash from result

#### Query contract address:
`axelard query wasm list-contract-by-code $CODE_ID --output json --chain-id devnet-wasm --node=http://devnet.rpc.axelar.dev:26657`


#### Query for transaction
`axelard ??? --chain-id devnet-wasm --node=http://devnet.rpc.axelar.dev:26657`


#### See if contract works (do a query)
```
CONTRACT_ADDR=axelar1mh5cjw2nlx495jl65cv49scnljryhwud6rhm7sxrwndvwf7nj2fssqucc2
QUERY='{"get_count":{}}'

axelard query wasm contract-state smart $CONTRACT_ADDR "$QUERY" --output json --chain-id devnet-wasm --node=http://devnet.rpc.axelar.dev:26657
```

#### Do a transaction on the contract
TRY_INCREMENT='{"increment": {}}'

`axelard tx wasm execute $CONTRACT_ADDR "$TRY_INCREMENT" --from test --gas-prices 0.025uwasm --gas auto --gas-adjustment 1.3 -y --chain-id devnet-wasm --node=http://devnet.rpc.axelar.dev:26657`

#### Reset count
```
RESET='{"reset": {"count": 0}}'

axelard tx wasm execute $CONTRACT_ADDR "$RESET" --from test --gas-prices 0.025uwasm --gas auto --gas-adjustment 1.3 -y --chain-id devnet-wasm --node=http://devnet.rpc.axelar.dev:26657
```

### Axelar WASM Devnet hello world contract deploy
CODE_ID: 2421

txHash: AB8265C0870CC48FEA6D34441903979CD3C92816AB43070E72D0D76E0A5C7A72

Contract address: axelar1mh5cjw2nlx495jl65cv49scnljryhwud6rhm7sxrwndvwf7nj2fssqucc2


#### Axelar GMP account (Gateway)?: axelar1dv4u5k73pzqrxlzujxg3qp8kvc3pje7jtdvu72npnt5zhq05ejcsn5qme5 - with or without an `s` at the end


# Axelar GMP contracts
- compile with:

`RUSTFLAGS='-C link-arg=-s' cargo wasm --locked --workspace --exclude ampd`

Optimize compile with:
```
docker run --rm -v "$(pwd)":/code \
  --mount type=volume,source="$(basename "$(pwd)")_cache",target=/target \
  --mount type=volume,source=registry_cache,target=/usr/local/cargo/registry \
  cosmwasm/workspace-optimizer:0.14.0
```

- ^ compiles all contracts

```
docker run --rm -v "$(pwd)":/code \
  --mount type=volume,source="devcontract_cache_gateway",target=/code/contracts/gateway/target \
  --mount type=volume,source=registry_cache,target=/usr/local/cargo/registry \
  cosmwasm/rust-optimizer:0.14.0 ./contracts/gateway
```

- ^ compiles only gateway contract

- deploy:

`axelard tx wasm store artifacts/gateway.wasm --from test --gas auto --gas-adjustment 5 -y --output json -b block --chain-id devnet-wasm --node=http://devnet.rpc.axelar.dev:26657 --gas-prices 0.1uwasm`

- gateway code id: 2426

- init contract:

`INIT='{"router_address":"TBD", "verifier_address": "TBD"}'` - data is JSON in Cosmos

`axelard tx wasm instantiate $CODE_ID "$INIT" --from test --label "MultiversX Gateway" --gas auto --gas-adjustment 5 -y --output json -b block --chain-id devnet-wasm --node=http://devnet.rpc.axelar.dev:26657 --gas-prices 0.1uwasm --no-admin`
