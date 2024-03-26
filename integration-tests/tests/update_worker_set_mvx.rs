use connection_router_api::{ChainName, Message};
use cosmwasm_std::Addr;
use cw_multi_test::Executor;
use integration_tests::contract::Contract;
use test_utils::Worker;
use crate::test_utils::KeyPair;

mod test_utils;

#[test]
fn worker_set_can_be_initialized_and_then_manually_updated_mvx() {
    let chains: Vec<ChainName> = vec![
        "MultiversX".to_string().try_into().unwrap(),
    ];
    let (mut protocol, _, mvx, _, initial_workers_mvx, min_worker_bond) =
        test_utils::mvx::setup_test_case_mvx();

    let simulated_worker_set = test_utils::workers_to_worker_set(&mut protocol, &initial_workers_mvx);

    let worker_set =
        test_utils::get_worker_set(&mut protocol.app, &mvx.multisig_prover);

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
        &mut protocol,
        &new_workers,
        min_worker_bond,
    );

    // remove old workers
    test_utils::deregister_workers(
        &mut protocol,
        &initial_workers_mvx,
    );

    let response = protocol
        .app
        .execute_contract(
            mvx.multisig_prover.admin_addr.clone(),
            mvx.multisig_prover.contract_addr.clone(),
            &multisig_prover::msg::ExecuteMsg::UpdateWorkerSet,
            &[],
        )
        .unwrap();

    // sign with old workers
    let session_id = test_utils::sign_proof(
        &mut protocol,
        &initial_workers_mvx,
        response,
    );

    let proof = test_utils::get_proof(
        &mut protocol.app,
        &mvx.multisig_prover,
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
        &mvx.voting_verifier,
        expected_new_worker_set.clone(),
    );

    // do voting
    test_utils::vote_true_for_worker_set(
        &mut protocol.app,
        &mvx.voting_verifier,
        &new_workers,
        poll_id,
    );

    test_utils::advance_at_least_to_height(&mut protocol.app, expiry);

    test_utils::end_poll(
        &mut protocol.app,
        &mvx.voting_verifier,
        poll_id,
    );

    test_utils::confirm_worker_set(
        &mut protocol.app,
        Addr::unchecked("relayer"),
        &mvx.multisig_prover,
    );

    let new_worker_set =
        test_utils::get_worker_set(&mut protocol.app, &mvx.multisig_prover);

    assert_eq!(new_worker_set, expected_new_worker_set);
}

#[test]
fn worker_set_cannot_be_updated_again_while_pending_worker_is_not_yet_confirmed_mvx() {
    let chains: Vec<ChainName> = vec![
        "MultiversX".to_string().try_into().unwrap(),
    ];
    let (mut protocol, _, mvx, _, initial_workers, min_worker_bond) =
        test_utils::mvx::setup_test_case_mvx();

    let simulated_worker_set = test_utils::workers_to_worker_set(&mut protocol, &initial_workers);

    let worker_set =
        test_utils::get_worker_set(&mut protocol.app, &mvx.multisig_prover);

    assert_eq!(worker_set, simulated_worker_set);

    // add third and fourth worker
    let mut first_wave_of_new_workers = Vec::new();
    let new_worker = Worker {
        addr: Addr::unchecked("worker5"),
        supported_chains: chains.clone(),
        key_pair: KeyPair::ED25519(test_utils::generate_key_ed25519(4)),
    };
    first_wave_of_new_workers.push(new_worker);
    let new_worker = Worker {
        addr: Addr::unchecked("worker6"),
        supported_chains: chains.clone(),
        key_pair: KeyPair::ED25519(test_utils::generate_key_ed25519(5)),
    };
    first_wave_of_new_workers.push(new_worker);

    test_utils::register_workers(
        &mut protocol,
        &first_wave_of_new_workers,
        min_worker_bond,
    );

    // remove old workers
    test_utils::deregister_workers(
        &mut protocol,
        &initial_workers,
    );

    let response = protocol
        .app
        .execute_contract(
            mvx.multisig_prover.admin_addr.clone(),
            mvx.multisig_prover.contract_addr.clone(),
            &multisig_prover::msg::ExecuteMsg::UpdateWorkerSet,
            &[],
        )
        .unwrap();

    let session_id = test_utils::sign_proof(&mut protocol, &initial_workers, response);

    let proof = test_utils::get_proof(&mut protocol.app, &mvx.multisig_prover, &session_id);

    // proof must be completed
    assert!(matches!(
        proof.status,
        multisig_prover::msg::ProofStatus::Completed { .. }
    ));
    assert_eq!(proof.message_ids.len(), 0);

    // starting and ending a poll for the first worker set rotation
    test_utils::mvx::execute_worker_set_poll_mvx(
        &mut protocol,
        &Addr::unchecked("relayer"),
        &mvx.voting_verifier,
        &first_wave_of_new_workers,
    );

    // try to rotate again. this should be ignored, because the first rotation is not yet confirmed
    let mut second_wave_of_new_workers = Vec::new();
    let new_worker = Worker {
        addr: Addr::unchecked("worker7"),
        supported_chains: chains.clone(),
        key_pair: KeyPair::ED25519(test_utils::generate_key_ed25519(7)),
    };
    second_wave_of_new_workers.push(new_worker);

    test_utils::register_workers(&mut protocol, &second_wave_of_new_workers, min_worker_bond);

    // Deregister old workers
    test_utils::deregister_workers(&mut protocol, &first_wave_of_new_workers);

    let response = mvx.multisig_prover.execute(
        &mut protocol.app,
        Addr::unchecked("relayer"),
        &multisig_prover::msg::ExecuteMsg::UpdateWorkerSet,
    );
    assert!(response.is_err());
}
