use cosmwasm_std::{Addr, HexBinary, Uint128};
use cw_multi_test::Executor;

use connection_router_api::{CrossChainId, Message};
use integration_tests::{connection_router_contract::ConnectionRouterContract, protocol::Protocol};
use test_utils::{Chain, Worker};

use crate::test_utils::AXL_DENOMINATION;

mod test_utils;

#[test]
fn single_message_can_be_verified_and_routed_and_proven_and_rewards_are_distributed_evm_to_mvx() {
    let (mut protocol, chain_evm, chain_mvx, workers_evm, workers_mvx, _) =
        test_utils::mvx::setup_test_case_mvx();

    let msgs = vec![Message {
        cc_id: CrossChainId {
            chain: chain_evm.chain_name.clone(),
            id: "0x88d7956fd7b6fcec846548d83bd25727f2585b4be3add21438ae9fbb34625924-3"
                .to_string()
                .try_into()
                .unwrap(),
        },
        source_address: "0xBf12773B49()0e1Deb57039061AAcFA2A87DEaC9b9"
            .to_string()
            .try_into()
            .unwrap(),
        destination_address: "erd1qqqqqqqqqqqqqpgqhe8t5jewej70zupmh44jurgn29psua5l2jps3ntjj3"
            .to_string()
            .try_into()
            .unwrap(),
        destination_chain: chain_mvx.chain_name.clone(),
        payload_hash: HexBinary::from_hex(
            "3e50a012285f8e7ec59b558179cd546c55c477ebe16202aac7d7747e25be03be",
        )
        .unwrap()
        .as_slice()
        .try_into()
        .unwrap(),
    }];
    let msg_ids: Vec<CrossChainId> = msgs.iter().map(|msg| msg.cc_id.clone()).collect();

    // start the flow by submitting the message to the gateway
    let (poll_id, expiry) =
        test_utils::verify_messages(&mut protocol.app, &chain_evm.gateway, &msgs);

    // do voting
    test_utils::vote_success_for_all_messages(
        &mut protocol.app,
        &chain_evm.voting_verifier,
        &msgs,
        &workers_evm,
        poll_id,
    );

    test_utils::advance_at_least_to_height(&mut protocol.app, expiry);

    test_utils::end_poll(&mut protocol.app, &chain_evm.voting_verifier, poll_id);

    // should be verified, now route
    test_utils::route_messages(&mut protocol.app, &chain_evm.gateway, &msgs);

    // check that the message can be found at the outgoing gateway
    let found_msgs =
        test_utils::get_messages_from_gateway(&mut protocol.app, &chain_mvx.gateway, &msg_ids);
    assert_eq!(found_msgs, msgs);

    // trigger signing and submit all necessary signatures
    let session_id = test_utils::construct_proof_and_sign(
        &mut protocol,
        &chain_mvx.multisig_prover,
        &msgs,
        &workers_mvx,
    );

    let proof = test_utils::get_proof(&mut protocol.app, &chain_mvx.multisig_prover, &session_id);

    // proof should be complete by now
    assert!(matches!(
        proof.status,
        multisig_prover::msg::ProofStatus::Completed { .. }
    ));
    assert_eq!(proof.message_ids, msg_ids);

    // Advance the height to be able to distribute rewards
    test_utils::advance_height(
        &mut protocol.app,
        u64::from(protocol.rewards_params.epoch_duration) * 2,
    );

    test_utils::distribute_rewards(
        &mut protocol,
        &chain_evm.chain_name,
        chain_evm.voting_verifier.contract_addr.clone(),
    );
    let protocol_multisig_address = protocol.multisig.contract_addr.clone();
    test_utils::distribute_rewards(
        &mut protocol,
        &chain_mvx.chain_name,
        protocol_multisig_address,
    );

    // rewards split evenly amongst all workers, but there are two contracts that rewards should have been distributed for
    let expected_rewards = Uint128::from(protocol.rewards_params.rewards_per_epoch)
        / Uint128::from(workers_evm.len() as u64 + workers_mvx.len() as u64)
        * Uint128::from(2u64);

    for worker in workers_evm {
        let balance = protocol
            .app
            .wrap()
            .query_balance(worker.addr, test_utils::AXL_DENOMINATION)
            .unwrap();
        assert_eq!(balance.amount, expected_rewards);
    }

    for worker in workers_mvx {
        let balance = protocol
            .app
            .wrap()
            .query_balance(worker.addr, test_utils::AXL_DENOMINATION)
            .unwrap();
        assert_eq!(balance.amount, expected_rewards);
    }
}

#[test]
fn single_message_can_be_verified_and_routed_and_proven_and_rewards_are_distributed_mvx_to_evm() {
    let (mut protocol, chain_evm, chain_mvx, workers_evm, workers_mvx, _) =
        test_utils::mvx::setup_test_case_mvx();

    let msgs = vec![Message {
        cc_id: CrossChainId {
            chain: chain_mvx.chain_name.clone(),
            id: "0x88d7956fd7b6fcec846548d83bd25727f2585b4be3add21438ae9fbb34625924-3"
                .to_string()
                .try_into()
                .unwrap(),
        },
        source_address: "erd1qqqqqqqqqqqqqpgqhe8t5jewej70zupmh44jurgn29psua5l2jps3ntjj3"
            .to_string()
            .try_into()
            .unwrap(),
        destination_address: "0xBf12773B49()0e1Deb57039061AAcFA2A87DEaC9b9"
            .to_string()
            .try_into()
            .unwrap(),
        destination_chain: chain_evm.chain_name,
        payload_hash: HexBinary::from_hex(
            "3e50a012285f8e7ec59b558179cd546c55c477ebe16202aac7d7747e25be03be",
        )
        .unwrap()
        .as_slice()
        .try_into()
        .unwrap(),
    }];
    let msg_ids: Vec<CrossChainId> = msgs.iter().map(|msg| msg.cc_id.clone()).collect();

    // start the flow by submitting the message to the gateway
    let (poll_id, expiry) =
        test_utils::verify_messages(&mut protocol.app, &chain_mvx.gateway, &msgs);

    // do voting
    test_utils::vote_success_for_all_messages(
        &mut protocol.app,
        &chain_mvx.voting_verifier,
        &msgs,
        &workers_mvx,
        poll_id,
    );

    test_utils::advance_at_least_to_height(&mut protocol.app, expiry);

    test_utils::end_poll(&mut protocol.app, &chain_mvx.voting_verifier, poll_id);

    // should be verified, now route
    test_utils::route_messages(&mut protocol.app, &chain_mvx.gateway, &msgs);

    // check that the message can be found at the outgoing gateway
    let found_msgs =
        test_utils::get_messages_from_gateway(&mut protocol.app, &chain_evm.gateway, &msg_ids);
    assert_eq!(found_msgs, msgs);
}
