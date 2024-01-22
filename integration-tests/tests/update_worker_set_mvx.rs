use connection_router::Message;
use cosmwasm_std::Addr;
use test_utils::Worker;
use crate::test_utils::KeyPair;

mod test_utils;

#[test]
fn worker_set_can_be_initialized_and_then_manually_updated_mvx() {
    let chains: Vec<connection_router::state::ChainName> = vec![
        "MultiversX".to_string().try_into().unwrap(),
    ];
    let (mut protocol, _, mvx, _, initial_workers_mvx, min_worker_bond) =
        test_utils::mvx::setup_test_case_mvx();

    let simulated_worker_set = test_utils::workers_to_worker_set(&mut protocol, &initial_workers_mvx);

    let worker_set =
        test_utils::get_worker_set(&mut protocol.app, &mvx.multisig_prover_address);

    assert_eq!(worker_set, simulated_worker_set);

    // add third and fourth worker
    let mut new_workers = Vec::new();
    let new_worker = Worker {
        addr: Addr::unchecked("worker5"),
        supported_chains: chains.clone(),
        key_pair: KeyPair::ED25519(test_utils::generate_key_ed25519(4)),
    };
    new_workers.push(new_worker);
    let new_worker = Worker {
        addr: Addr::unchecked("worker6"),
        supported_chains: chains.clone(),
        key_pair: KeyPair::ED25519(test_utils::generate_key_ed25519(5)),
    };
    new_workers.push(new_worker);

    let expected_new_worker_set = test_utils::workers_to_worker_set(&mut protocol, &new_workers);

    test_utils::register_workers(
        &mut protocol.app,
        protocol.service_registry_address.clone(),
        protocol.multisig_address.clone(),
        protocol.governance_address.clone(),
        protocol.genesis_address.clone(),
        &new_workers,
        protocol.service_name.clone(),
        min_worker_bond,
    );

    // remove old workers
    test_utils::deregister_workers(
        &mut protocol.app,
        protocol.service_registry_address.clone(),
        protocol.governance_address.clone(),
        &initial_workers_mvx,
        protocol.service_name.clone(),
    );

    let response = test_utils::update_worker_set(
        &mut protocol.app,
        Addr::unchecked("relayer"),
        mvx.multisig_prover_address.clone(),
    );

    // sign with old workers
    let session_id = test_utils::sign_proof(
        &mut protocol.app,
        &protocol.multisig_address,
        &initial_workers_mvx,
        response,
    );

    let proof = test_utils::get_proof(
        &mut protocol.app,
        &mvx.multisig_prover_address,
        &session_id,
    );
    assert!(matches!(
        proof.status,
        multisig_prover::msg::ProofStatus::Completed { .. }
    ));

    assert_eq!(proof.message_ids.len(), 0);

    let (poll_id, expiry) = test_utils::mvx::create_worker_set_poll_mvx(
        &mut protocol.app,
        Addr::unchecked("relayer"),
        mvx.voting_verifier_address.clone(),
        expected_new_worker_set.clone(),
    );

    // do voting
    test_utils::vote_true_for_worker_set(
        &mut protocol.app,
        &mvx.voting_verifier_address,
        &new_workers,
        poll_id,
    );

    test_utils::advance_at_least_to_height(&mut protocol.app, expiry);

    test_utils::end_poll(
        &mut protocol.app,
        &mvx.voting_verifier_address,
        poll_id,
    );

    test_utils::confirm_worker_set(
        &mut protocol.app,
        Addr::unchecked("relayer"),
        mvx.multisig_prover_address.clone(),
    );

    let new_worker_set =
        test_utils::get_worker_set(&mut protocol.app, &mvx.multisig_prover_address);

    assert_eq!(new_worker_set, expected_new_worker_set);
}

#[test]
fn worker_set_can_be_initialized_and_then_automatically_updated_during_proof_construction_mvx() {
    let chains: Vec<connection_router::state::ChainName> = vec![
        "MultiversX".to_string().try_into().unwrap(),
    ];
    let (mut protocol, _, mvx, _, initial_workers, min_worker_bond) =
        test_utils::mvx::setup_test_case_mvx();

    let simulated_worker_set = test_utils::workers_to_worker_set(&mut protocol, &initial_workers);

    let worker_set =
        test_utils::get_worker_set(&mut protocol.app, &mvx.multisig_prover_address);

    assert_eq!(worker_set, simulated_worker_set);

    // add third and fourth worker
    let mut new_workers = Vec::new();
    let new_worker = Worker {
        addr: Addr::unchecked("worker5"),
        supported_chains: chains.clone(),
        key_pair: KeyPair::ED25519(test_utils::generate_key_ed25519(4)),
    };
    new_workers.push(new_worker);
    let new_worker = Worker {
        addr: Addr::unchecked("worker6"),
        supported_chains: chains.clone(),
        key_pair: KeyPair::ED25519(test_utils::generate_key_ed25519(5)),
    };
    new_workers.push(new_worker);

    let expected_new_worker_set = test_utils::workers_to_worker_set(&mut protocol, &new_workers);

    test_utils::register_workers(
        &mut protocol.app,
        protocol.service_registry_address.clone(),
        protocol.multisig_address.clone(),
        protocol.governance_address.clone(),
        protocol.genesis_address.clone(),
        &new_workers,
        protocol.service_name.clone(),
        min_worker_bond,
    );

    // remove old workers
    test_utils::deregister_workers(
        &mut protocol.app,
        protocol.service_registry_address.clone(),
        protocol.governance_address.clone(),
        &initial_workers,
        protocol.service_name.clone(),
    );

    let session_id = test_utils::construct_proof_and_sign(
        &mut protocol.app,
        &mvx.multisig_prover_address,
        &protocol.multisig_address,
        &Vec::<Message>::new(),
        &initial_workers,
    );

    let proof = test_utils::get_proof(
        &mut protocol.app,
        &mvx.multisig_prover_address,
        &session_id,
    );
    assert!(matches!(
        proof.status,
        multisig_prover::msg::ProofStatus::Completed { .. }
    ));

    assert_eq!(proof.message_ids.len(), 0);

    let (poll_id, expiry) = test_utils::mvx::create_worker_set_poll_mvx(
        &mut protocol.app,
        Addr::unchecked("relayer"),
        mvx.voting_verifier_address.clone(),
        expected_new_worker_set.clone(),
    );

    // do voting
    test_utils::vote_true_for_worker_set(
        &mut protocol.app,
        &mvx.voting_verifier_address,
        &new_workers,
        poll_id,
    );

    test_utils::advance_at_least_to_height(&mut protocol.app, expiry);

    test_utils::end_poll(
        &mut protocol.app,
        &mvx.voting_verifier_address,
        poll_id,
    );

    test_utils::confirm_worker_set(
        &mut protocol.app,
        Addr::unchecked("relayer"),
        mvx.multisig_prover_address.clone(),
    );

    let new_worker_set =
        test_utils::get_worker_set(&mut protocol.app, &mvx.multisig_prover_address);

    assert_eq!(new_worker_set, expected_new_worker_set);
}
