use cosmwasm_std::{Addr, coins, HexBinary, Uint128, Uint256};
use cw_multi_test::{App, AppResponse, ContractWrapper, Executor};

use axelar_wasm_std::{nonempty, Participant, Threshold};
use axelar_wasm_std::voting::PollId;
use connection_router_api::{ChainName, CrossChainId, Message};
use integration_tests::{connection_router_contract::ConnectionRouterContract, protocol::Protocol};
use integration_tests::contract::Contract;
use integration_tests::gateway_contract::GatewayContract;
use integration_tests::multisig_prover_contract::MultisigProverContract;
use integration_tests::voting_verifier_contract::VotingVerifierContract;
use multisig::key::{KeyType, PublicKey};
use multisig::worker_set::WorkerSet;
use multisig_prover::encoding::{Encoder, make_operators};
use rewards::state::PoolId;

use crate::test_utils::{advance_at_least_to_height, AXL_DENOMINATION, Chain, create_worker_set_poll, end_poll, generate_key, generate_key_ed25519, get_worker_set_poll_id_and_expiry, KeyPair, PollExpiryBlock, register_service, register_workers, setup_chain, setup_protocol, vote_true_for_worker_set, Worker, workers_to_worker_set};

pub fn create_worker_set_poll_mvx(
    app: &mut App,
    relayer_addr: Addr,
    voting_verifier: &VotingVerifierContract,
    worker_set: WorkerSet,
) -> (PollId, PollExpiryBlock) {
    let response = voting_verifier.execute(
        app,
        relayer_addr.clone(),
        &voting_verifier::msg::ExecuteMsg::VerifyWorkerSet {
            message_id: "multiversx-0".parse().unwrap(),
            new_operators: make_operators(worker_set.clone(), Encoder::Mvx),
        },
    );
    assert!(response.is_ok());

    get_worker_set_poll_id_and_expiry(response.unwrap())
}

pub fn execute_worker_set_poll_mvx(
    protocol: &mut Protocol,
    relayer_addr: &Addr,
    voting_verifier: &VotingVerifierContract,
    new_workers: &Vec<Worker>,
) {
    // Create worker set
    let new_worker_set = workers_to_worker_set(protocol, new_workers);

    // Create worker set poll
    let (poll_id, expiry) = create_worker_set_poll_mvx(
        &mut protocol.app,
        relayer_addr.clone(),
        voting_verifier,
        new_worker_set.clone(),
    );

    // Vote for the worker set
    vote_true_for_worker_set(&mut protocol.app, voting_verifier, new_workers, poll_id);

    // Advance to expiration height
    advance_at_least_to_height(&mut protocol.app, expiry);

    // End the poll
    end_poll(&mut protocol.app, voting_verifier, poll_id);
}

pub fn setup_chain_mvx(protocol: &mut Protocol, chain_name: ChainName) -> Chain {
    let voting_verifier = VotingVerifierContract::instantiate_contract(
        protocol,
        "doesn't matter".to_string().try_into().unwrap(),
        Threshold::try_from((9, 10)).unwrap().try_into().unwrap(),
        chain_name.clone(),
    );

    let gateway = GatewayContract::instantiate_contract(
        &mut protocol.app,
        protocol.connection_router.contract_address().clone(),
        voting_verifier.contract_addr.clone(),
    );

    let multisig_prover_admin = Addr::unchecked(chain_name.to_string() + "prover_admin");
    let multisig_prover = MultisigProverContract::instantiate_contract_mvx(
        protocol,
        multisig_prover_admin.clone(),
        gateway.contract_addr.clone(),
        voting_verifier.contract_addr.clone(),
        chain_name.to_string(),
    );

    let response = multisig_prover.execute(
        &mut protocol.app,
        multisig_prover_admin,
        &multisig_prover::msg::ExecuteMsg::UpdateWorkerSet,
    );
    assert!(response.is_ok());

    let response = protocol.multisig.execute(
        &mut protocol.app,
        protocol.governance_address.clone(),
        &multisig::msg::ExecuteMsg::AuthorizeCaller {
            contract_address: multisig_prover.contract_addr.clone(),
        },
    );
    assert!(response.is_ok());

    let response = protocol.connection_router.execute(
        &mut protocol.app,
        protocol.governance_address.clone(),
        &connection_router_api::msg::ExecuteMsg::RegisterChain {
            chain: chain_name.clone(),
            gateway_address: gateway.contract_addr.to_string().try_into().unwrap(),
        },
    );
    assert!(response.is_ok());

    let response = protocol.rewards.execute_with_funds(
        &mut protocol.app,
        protocol.genesis_address.clone(),
        &rewards::msg::ExecuteMsg::AddRewards {
            pool_id: PoolId {
                chain_name: chain_name.clone(),
                contract: voting_verifier.contract_addr.clone(),
            },
        },
        &coins(1000, AXL_DENOMINATION),
    );
    assert!(response.is_ok());

    let response = protocol.rewards.execute_with_funds(
        &mut protocol.app,
        protocol.genesis_address.clone(),
        &rewards::msg::ExecuteMsg::AddRewards {
            pool_id: PoolId {
                chain_name: chain_name.clone(),
                contract: protocol.multisig.contract_addr.clone(),
            },
        },
        &coins(1000, AXL_DENOMINATION),
    );
    assert!(response.is_ok());

    Chain {
        gateway,
        voting_verifier,
        multisig_prover,
        chain_name,
    }
}

pub fn setup_test_case_mvx() -> (Protocol, Chain, Chain, Vec<Worker>, Vec<Worker>, Uint128) {
    let mut protocol = setup_protocol("validators".to_string().try_into().unwrap());
    let chains: Vec<ChainName> = vec![
        "Ethereum".to_string().try_into().unwrap(),
        "MultiversX".to_string().try_into().unwrap(),
    ];
    let workers_evm = vec![
        Worker {
            addr: Addr::unchecked("worker1"),
            supported_chains: vec![chains.get(0).unwrap().clone()],
            key_pair: KeyPair::ECDSA(generate_key(0)),
        },
        Worker {
            addr: Addr::unchecked("worker2"),
            supported_chains: vec![chains.get(0).unwrap().clone()],
            key_pair: KeyPair::ECDSA(generate_key(1)),
        },
    ];
    let workers_mvx = vec![
        Worker {
            addr: Addr::unchecked("worker3"),
            supported_chains: vec![chains.get(1).unwrap().clone()],
            key_pair: KeyPair::ED25519(generate_key_ed25519(2)),
        },
        Worker {
            addr: Addr::unchecked("worker4"),
            supported_chains: vec![chains.get(1).unwrap().clone()],
            key_pair: KeyPair::ED25519(generate_key_ed25519(3)),
        },
    ];
    let min_worker_bond = Uint128::new(100);
    register_service(&mut protocol, min_worker_bond);

    register_workers(&mut protocol, &workers_evm, min_worker_bond);
    register_workers(&mut protocol, &workers_mvx, min_worker_bond);

    let chain_evm = setup_chain(&mut protocol, chains.get(0).unwrap().clone());
    let chain_mvx = setup_chain_mvx(&mut protocol, chains.get(1).unwrap().clone());
    (
        protocol,
        chain_evm,
        chain_mvx,
        workers_evm,
        workers_mvx,
        min_worker_bond,
    )
}
