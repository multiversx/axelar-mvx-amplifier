use crate::test_utils::{generate_key, instantiate_gateway, instantiate_multisig_prover, instantiate_voting_verifier, register_service, register_workers, setup_chain, setup_protocol, Chain, KeyPair, Protocol, Worker, AXL_DENOMINATION, PollExpiryBlock, get_worker_set_poll_id_and_expiry, generate_key_ed25519};
use axelar_wasm_std::{nonempty, Participant, Threshold};
use connection_router::state::ChainName;
use cosmwasm_std::{coins, Addr, HexBinary, Uint128, Uint256};
use cw_multi_test::{App, AppResponse, ContractWrapper, Executor};
use axelar_wasm_std::voting::PollId;
use multisig::key::{KeyType, PublicKey};
use multisig::worker_set::WorkerSet;
use multisig_prover::encoding::{Encoder, make_operators};

pub fn create_worker_set_poll_mvx(
    app: &mut App,
    relayer_addr: Addr,
    voting_verifier: Addr,
    worker_set: WorkerSet,
) -> (PollId, PollExpiryBlock) {
    let response = app.execute_contract(
        relayer_addr.clone(),
        voting_verifier.clone(),
        &voting_verifier::msg::ExecuteMsg::VerifyWorkerSet {
            message_id: "multiversx:00".parse().unwrap(),
            new_operators: make_operators(worker_set.clone(), Encoder::Mvx),
        },
        &[],
    );
    assert!(response.is_ok());

    get_worker_set_poll_id_and_expiry(response.unwrap())
}

pub fn setup_chain_mvx(protocol: &mut Protocol, chain_name: ChainName) -> Chain {
    let voting_verifier_address = instantiate_voting_verifier(
        &mut protocol.app,
        voting_verifier::msg::InstantiateMsg {
            service_registry_address: protocol
                .service_registry_address
                .to_string()
                .try_into()
                .unwrap(),
            service_name: protocol.service_name.clone(),
            source_gateway_address: "doesn't matter".to_string().try_into().unwrap(),
            voting_threshold: Threshold::try_from((9, 10)).unwrap().try_into().unwrap(),
            block_expiry: 10,
            confirmation_height: 5,
            source_chain: chain_name.clone(),
            rewards_address: protocol.rewards_address.to_string(),
        },
    );
    let gateway_address = instantiate_gateway(
        &mut protocol.app,
        gateway::msg::InstantiateMsg {
            router_address: protocol.router_address.to_string(),
            verifier_address: voting_verifier_address.to_string(),
        },
    );
    let multisig_prover_address = instantiate_multisig_prover(
        &mut protocol.app,
        multisig_prover::msg::InstantiateMsg {
            admin_address: Addr::unchecked("doesn't matter").to_string(),
            gateway_address: gateway_address.to_string(),
            multisig_address: protocol.multisig_address.to_string(),
            service_registry_address: protocol.service_registry_address.to_string(),
            voting_verifier_address: voting_verifier_address.to_string(),
            destination_chain_id: Uint256::zero(),
            signing_threshold: Threshold::try_from((2, 3)).unwrap().try_into().unwrap(),
            service_name: protocol.service_name.to_string(),
            chain_name: chain_name.to_string(),
            worker_set_diff_threshold: 1,
            encoder: multisig_prover::encoding::Encoder::Mvx,
            key_type: multisig::key::KeyType::Ed25519,
        },
    );
    let response = protocol.app.execute_contract(
        Addr::unchecked("doesn't matter"),
        multisig_prover_address.clone(),
        &multisig_prover::msg::ExecuteMsg::UpdateWorkerSet,
        &[],
    );
    assert!(response.is_ok());
    let response = protocol.app.execute_contract(
        protocol.governance_address.clone(),
        protocol.multisig_address.clone(),
        &multisig::msg::ExecuteMsg::AuthorizeCaller {
            contract_address: multisig_prover_address.clone(),
        },
        &[],
    );
    assert!(response.is_ok());

    let response = protocol.app.execute_contract(
        protocol.governance_address.clone(),
        protocol.router_address.clone(),
        &connection_router::msg::ExecuteMsg::RegisterChain {
            chain: chain_name.clone(),
            gateway_address: gateway_address.to_string(),
        },
        &[],
    );
    assert!(response.is_ok());

    let response = protocol.app.execute_contract(
        protocol.genesis_address.clone(),
        protocol.rewards_address.clone(),
        &rewards::msg::ExecuteMsg::AddRewards {
            contract_address: voting_verifier_address.to_string(),
        },
        &coins(1000, AXL_DENOMINATION),
    );
    assert!(response.is_ok());

    Chain {
        gateway_address,
        voting_verifier_address,
        multisig_prover_address,
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
    register_service(
        &mut protocol.app,
        protocol.service_registry_address.clone(),
        protocol.governance_address.clone(),
        protocol.service_name.clone(),
        min_worker_bond.clone(),
    );

    register_workers(
        &mut protocol.app,
        protocol.service_registry_address.clone(),
        protocol.multisig_address.clone(),
        protocol.governance_address.clone(),
        protocol.genesis_address.clone(),
        &workers_evm,
        protocol.service_name.clone(),
        min_worker_bond,
    );
    register_workers(
        &mut protocol.app,
        protocol.service_registry_address.clone(),
        protocol.multisig_address.clone(),
        protocol.governance_address.clone(),
        protocol.genesis_address.clone(),
        &workers_mvx,
        protocol.service_name.clone(),
        min_worker_bond,
    );

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
