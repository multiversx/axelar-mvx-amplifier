use bech32::{self, FromBase32};
use cosmwasm_std::{HexBinary, Uint256};
use itertools::Itertools;
use multisig::key::Signature;
use multisig::msg::Signer;
use multiversx_sc_codec::top_encode_to_vec_u8;
use sha3::{Digest, Keccak256};

use crate::types::{CommandBatch, Operator};
use crate::{error::ContractError, state::WorkerSet};

use super::Data;

pub fn command_params(
    source_chain: String,
    source_address: String,
    destination_address: String,
    payload_hash: &[u8; 32],
) -> Result<HexBinary, ContractError> {
    let map_addr_err = |_| ContractError::InvalidMessage {
        reason: format!(
            "destination_address is not a valid Mvx address: {}",
            destination_address
        ),
    };

    let (_, data, _) = bech32::decode(&destination_address).map_err(map_addr_err)?;
    let addr_vec = Vec::<u8>::from_base32(&data).map_err(map_addr_err)?;
    let destination_address =
        <[u8; 32]>::try_from(addr_vec).map_err(|_| ContractError::InvalidMessage {
            reason: format!(
                "destination_address is not a valid Mvx address: {}",
                destination_address
            ),
        })?;

    Ok(top_encode_to_vec_u8(&(
        source_chain,
        source_address,
        destination_address,
        payload_hash,
    ))
    .expect("couldn't serialize command as mvx")
    .into())
}

pub fn transfer_operatorship_params(worker_set: &WorkerSet) -> Result<HexBinary, ContractError> {
    let mut operators: Vec<([u8; 32], Uint256)> = worker_set
        .signers
        .iter()
        .map(|signer| {
            (
                <[u8; 32]>::try_from(signer.pub_key.as_ref())
                    .expect("couldn't convert pubkey to ed25519 public key"),
                signer.weight,
            )
        })
        .collect();
    // The order doesn't matter currently for MultiversX, but keeping this for consistency
    operators.sort_by_key(|op| op.0.clone());
    let (addresses, weights): (Vec<[u8; 32]>, Vec<Vec<u8>>) = operators
        .iter()
        .map(|operator| (operator.0, uint256_to_compact_vec(operator.1)))
        .unzip();

    let threshold = uint256_to_compact_vec(worker_set.threshold);

    Ok(top_encode_to_vec_u8(&(addresses, weights, threshold))
        .expect("couldn't serialize command as mvx")
        .into())
}

pub fn msg_digest(command_batch: &CommandBatch) -> HexBinary {
    // MultiversX is just mimicking EVM here
    let unsigned = [
        "\x19MultiversX Signed Message:\n".as_bytes(), // Keccek256 hash length = 32
        encode(&command_batch.data).as_slice(),
    ]
    .concat();

    Keccak256::digest(unsigned).as_slice().into()
}

pub fn encode(data: &Data) -> HexBinary {
    // destination chain id is a string for MultiversX
    let destination_chain_id = uint256_to_compact_vec(data.destination_chain_id);

    let (commands_ids, command_types, command_params): (Vec<[u8; 32]>, Vec<String>, Vec<Vec<u8>>) =
        data.commands
            .iter()
            .map(|command| {
                (
                    make_command_id(&command.id),
                    command.ty.to_string(),
                    command.params.to_vec(),
                )
            })
            .multiunzip();

    top_encode_to_vec_u8(&(
        destination_chain_id,
        commands_ids,
        command_types,
        command_params,
    ))
    .expect("couldn't serialize command as mvx")
    .into()
}

// pub fn encode_execute_data(
//     command_batch: &CommandBatch,
//     quorum: Uint256,
//     signers: Vec<(Signer, Option<Signature>)>,
// ) -> Result<HexBinary, ContractError> {
//     let input = top_encode_to_vec_u8(&(
//         encode(&command_batch.data).to_vec(),
//         encode_proof(quorum, signers)?.to_vec(),
//     ))?;
//     Ok(input.into())
// }

fn uint256_to_compact_vec(value: Uint256) -> Vec<u8> {
    if value.is_zero() {
        return Vec::new();
    }

    let bytes = value.to_be_bytes();
    let mut slice_from = 0;
    for (i, byte) in bytes.iter().enumerate() {
        if *byte != 0 {
            slice_from = i;
            break;
        }
    }

    bytes[slice_from..].to_vec()
}

fn make_command_id(command_id: &HexBinary) -> [u8; 32] {
    // command-ids are fixed length sequences
    command_id
        .to_vec()
        .try_into()
        .expect("couldn't convert command id to 32 byte array")
}

// fn encode_proof(
//     threshold: Uint256,
//     signers: Vec<(Signer, Option<Signature>)>,
// ) -> Result<HexBinary, ContractError> {
//     let mut operators = make_operators_with_sigs(signers);
//     operators.sort(); // sorting doesn't matter for MultiversX currently, leaving for consistency
//
//     let (addresses, weights, signatures): (Vec<_>, Vec<_>, Vec<_>) = operators
//         .iter()
//         .map(|op| {
//             (
//                 <[u8; 32]>::try_from(op.address.as_ref())?,
//                 uint256_to_compact_vec(op.weight),
//                 <[u8; 64]>::try_from(op.signature.as_ref().unwrap().as_ref())?,
//             )
//         })
//         .multiunzip()
//         .map_err(|_| ContractError::InvalidMessage {
//             reason: format!(
//                 "destination_address is not a valid Mvx address: {}",
//                 destination_address
//             ),
//         })?;
//
//     let threshold = uint256_to_compact_vec(threshold);
//     Ok(top_encode_to_vec_u8(&(addresses, weights, threshold, signatures))?.into())
// }

fn make_operators_with_sigs(signers_with_sigs: Vec<(Signer, Option<Signature>)>) -> Vec<Operator> {
    signers_with_sigs
        .into_iter()
        .map(|(signer, sig)| Operator {
            address: signer.pub_key.into(),
            weight: signer.weight,
            signature: sig,
        })
        .collect()
}

#[cfg(test)]
mod test {
    use crate::encoding::mvx::{encode, make_command_id, msg_digest, uint256_to_compact_vec};
    use crate::encoding::{CommandBatchBuilder, Data};
    use crate::types::Command;
    use crate::{
        encoding::mvx::{command_params, transfer_operatorship_params},
        test::test_data,
    };
    use connection_router::state::Message;
    use cosmwasm_std::{HexBinary, Uint256};

    #[test]
    fn test_command_params() {
        let res = command_params(
            "Ethereum".into(),
            "00".into(),
            "erd1qqqqqqqqqqqqqpgqhe8t5jewej70zupmh44jurgn29psua5l2jps3ntjj3".into(),
            &[2; 32],
        );
        assert!(res.is_ok());

        let res = res.unwrap();

        // 00000008 - length of text
        // 457468657265756d - 'Ethereum' as hex
        // 00000002 - length of text
        // 3030 - '00' as hex
        // 00000000000000000500be4eba4b2eccbcf1703bbd6b2e0d1351430e769f5483 - bech32 destination address as hex
        // 0202020202020202020202020202020202020202020202020202020202020202 - payload hash as hex
        assert_eq!(res.to_hex(), "00000008457468657265756d00000002303000000000000000000500be4eba4b2eccbcf1703bbd6b2e0d1351430e769f54830202020202020202020202020202020202020202020202020202020202020202");
    }

    #[test]
    fn test_invalid_destination_address() {
        let res = command_params(
            "Ethereum".into(),
            "00".into(),
            "01".repeat(32).into(),
            &[2; 32],
        );
        assert!(!res.is_ok());

        let res = command_params(
            "Ethereum".into(),
            "00".into(),
            "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw".into(),
            &[2; 32],
        );
        assert!(!res.is_ok());
    }

    #[test]
    fn test_transfer_operatorship_params() {
        let worker_set = test_data::new_worker_set_ed25519();
        let res = transfer_operatorship_params(&worker_set);
        assert!(res.is_ok());

        let res = res.unwrap();

        // 00000002 - length of operators vec
        // ca5b4abdf9eec1f8e2d12c187d41ddd054c81979cae9e8ee9f4ecab901cac5b6 - first public key
        // ef637606f3144ee46343ba4a25c261b5c400ade88528e876f3deababa22a4449 - second public key
        // 00000002 - length of weights vec
        // 00000001 0a - length of biguint weight followed by 10 as hex
        // 00000001 0a
        // 00000001 14 - length of biguint threshold followed by 20 as hex
        assert_eq!(res.to_hex(), "00000002ca5b4abdf9eec1f8e2d12c187d41ddd054c81979cae9e8ee9f4ecab901cac5b6ef637606f3144ee46343ba4a25c261b5c400ade88528e876f3deababa22a444900000002000000010a000000010a0000000114");
    }

    #[test]
    fn test_msg_digest() {
        let mut builder = CommandBatchBuilder::new(1u128.into(), crate::encoding::Encoder::Mvx);
        let _ = builder
            .add_message(Message {
                cc_id: "ethereum:foobar:1".parse().unwrap(),
                destination_address:
                    "erd1qqqqqqqqqqqqqpgqhe8t5jewej70zupmh44jurgn29psua5l2jps3ntjj3"
                        .parse()
                        .unwrap(),
                destination_chain: "multiversx".parse().unwrap(),
                source_address: "0x00".parse().unwrap(),
                payload_hash: [1; 32],
            })
            .unwrap();
        let batch = builder.build().unwrap();
        let msg = msg_digest(&batch);
        assert_eq!(msg.len(), 32);

        let mut builder = CommandBatchBuilder::new(1u128.into(), crate::encoding::Encoder::Mvx);
        let _ = builder
            .add_message(Message {
                cc_id: "ethereum:foobar:2".parse().unwrap(),
                destination_address:
                    "erd1qqqqqqqqqqqqqpgqvc7gdl0p4s97guh498wgz75k8sav6sjfjlwqh679jy"
                        .parse()
                        .unwrap(),
                destination_chain: "multiversx".parse().unwrap(),
                source_address: "0x00".parse().unwrap(),
                payload_hash: [2; 32],
            })
            .unwrap();

        let batch = builder.build().unwrap();
        let msg2 = msg_digest(&batch);
        assert_ne!(msg, msg2);
    }

    #[test]
    fn test_encode() {
        let source_chain = "Ethereum";
        let source_address = "00";
        let destination_address = "erd1qqqqqqqqqqqqqpgqhe8t5jewej70zupmh44jurgn29psua5l2jps3ntjj3";
        let payload_hash = [2; 32];
        let destination_chain_id = 68u8; // 'D' string as number
        let command_id = HexBinary::from_hex(&"FF".repeat(32)).unwrap();
        let data = Data {
            destination_chain_id: destination_chain_id.into(),
            commands: vec![Command {
                id: command_id.clone(),
                ty: crate::types::CommandType::ApproveContractCall,
                params: command_params(
                    source_chain.into(),
                    source_address.into(),
                    destination_address.into(),
                    &payload_hash,
                )
                .unwrap(),
            }],
        };
        let encoded = encode(&data);

        // 00000001 - length of text
        // 44 - 'D' as hex
        // 00000001 - length of command ids
        // ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff - command id
        // 00000001 - length of commands
        // 00000013 - length of text
        // 617070726f7665436f6e747261637443616c6c - 'approveContractCall' as hex
        // 00000001 - length of params
        // 00000052 - length of param
        // 00000008457468657265756d00000002303000000000000000000500be4eba4b2eccbcf1703bbd6b2e0d1351430e769f54830202020202020202020202020202020202020202020202020202020202020202 - params
        assert_eq!(encoded.to_hex(), "000000014400000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000100000013617070726f7665436f6e747261637443616c6c000000010000005200000008457468657265756d00000002303000000000000000000500be4eba4b2eccbcf1703bbd6b2e0d1351430e769f54830202020202020202020202020202020202020202020202020202020202020202");
    }

    // #[test]
    // fn test_make_operators() {
    //     let worker_set = test_data::new_worker_set();
    //     let mut expected: Vec<(HexBinary, _)> = worker_set
    //         .clone()
    //         .signers
    //         .into_iter()
    //         .map(|s| (s.pub_key.into(), s.weight))
    //         .collect();
    //     expected.sort_by_key(|op| op.0.clone());
    //
    //     let operators = make_operators(worker_set.clone());
    //     let expected_operators = Operators {
    //         weights_by_addresses: expected,
    //         threshold: worker_set.threshold,
    //     };
    //     assert_eq!(operators, expected_operators);
    // }

    // #[test]
    // fn test_encode_proof() {
    //     let signers = vec![
    //         (Signer {
    //             address: Addr::unchecked("axelarvaloper1ff675m593vve8yh82lzhdnqfpu7m23cxstr6h4"),
    //             weight: Uint256::from(10u128),
    //             pub_key: PublicKey::Ecdsa(
    //                 HexBinary::from_hex(
    //                     "03c6ddb0fcee7b528da1ef3c9eed8d51eeacd7cc28a8baa25c33037c5562faa6e4",
    //                 )
    //                     .unwrap(),
    //             ),
    //         },
    //          Some(Signature::EcdsaRecoverable(
    //              HexBinary::from_hex("283786d844a7c4d1d424837074d0c8ec71becdcba4dd42b5307cb543a0e2c8b81c10ad541defd5ce84d2a608fc454827d0b65b4865c8192a2ea1736a5c4b72021b").unwrap().try_into().unwrap()))),
    //         (Signer {
    //             address: Addr::unchecked("axelarvaloper1x86a8prx97ekkqej2x636utrdu23y8wupp9gk5"),
    //             weight: Uint256::from(10u128),
    //             pub_key: PublicKey::Ecdsa(
    //                 HexBinary::from_hex(
    //                     "03d123ce370b163acd576be0e32e436bb7e63262769881d35fa3573943bf6c6f81",
    //                 )
    //                     .unwrap(),
    //             ),
    //         },
    //          Some(Signature::EcdsaRecoverable(
    //              HexBinary::from_hex("283786d844a7c4d1d424837074d0c8ec71becdcba4dd42b5307cb543a0e2c8b81c10ad541defd5ce84d2a608fc454827d0b65b4865c8192a2ea1736a5c4b72021b").unwrap().try_into().unwrap())))];
    //
    //     let quorum = Uint256::from(10u128);
    //     let proof = encode_proof(quorum, signers.clone());
    //
    //     assert!(proof.is_ok());
    //     let proof = proof.unwrap();
    //     let decoded_proof: Result<(Vec<Vec<u8>>, Vec<u128>, u128, Vec<Vec<u8>>), _> =
    //         from_bytes(&proof);
    //     assert!(decoded_proof.is_ok());
    //     let (operators, weights, quorum_decoded, signatures): (
    //         Vec<Vec<u8>>,
    //         Vec<u128>,
    //         u128,
    //         Vec<Vec<u8>>,
    //     ) = decoded_proof.unwrap();
    //
    //     assert_eq!(operators.len(), signers.len());
    //     assert_eq!(weights.len(), signers.len());
    //     assert_eq!(signatures.len(), signers.len());
    //     assert_eq!(quorum_decoded, 10u128);
    //
    //     for i in 0..signers.len() {
    //         assert_eq!(
    //             operators[i],
    //             HexBinary::from(signers[i].0.pub_key.clone()).to_vec()
    //         );
    //         assert_eq!(weights[i], 10u128);
    //         assert_eq!(
    //             signatures[i],
    //             HexBinary::from(signers[i].1.clone().unwrap().as_ref()).to_vec()
    //         );
    //     }
    // }

    // #[test]
    // fn test_encode_execute_data() {
    //     let approval = HexBinary::from_hex("8a02010000000000000002000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000020213617070726f7665436f6e747261637443616c6c13617070726f7665436f6e747261637443616c6c0249034554480330783000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000004c064158454c415203307831000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000087010121037286a4f1177bea06c8e15cf6ec3df0b7747a01ac2329ca2999dfd74eff59902801640000000000000000000000000000000a0000000000000000000000000000000141ef5ce016a4beed7e11761e5831805e962fca3d8901696a61a6ffd3af2b646bdc3740f64643bdb164b8151d1424eb4943d03f71e71816c00726e2d68ee55600c600").unwrap();
    //
    //     let zero_addr = "00".repeat(32);
    //
    //     let data = Data {
    //         destination_chain_id: 1u32.into(),
    //         commands: vec![
    //             Command {
    //                 id: HexBinary::from_hex(
    //                     "0000000000000000000000000000000000000000000000000000000000000001",
    //                 )
    //                     .unwrap(),
    //                 ty: crate::types::CommandType::ApproveContractCall,
    //                 params: command_params("ETH".into(), "0x0".into(), zero_addr.clone(), &[0; 32])
    //                     .unwrap(),
    //             },
    //             Command {
    //                 id: HexBinary::from_hex(
    //                     "0000000000000000000000000000000000000000000000000000000000000002",
    //                 )
    //                     .unwrap(),
    //                 ty: crate::types::CommandType::ApproveContractCall,
    //                 params: command_params("AXELAR".into(), "0x1".into(), zero_addr, &[0; 32])
    //                     .unwrap(),
    //             },
    //         ],
    //     };
    //
    //     let command_batch = CommandBatch {
    //         message_ids: vec![],
    //         id: BatchID::new(&vec!["foobar".to_string()], None),
    //         data,
    //         encoder: crate::encoding::Encoder::Bcs,
    //     };
    //     let quorum = 10u128;
    //
    //     let signer = Signer {
    //         address: Addr::unchecked("axelarvaloper1x86a8prx97ekkqej2x636utrdu23y8wupp9gk5"),
    //         weight: Uint256::from(100u128),
    //         pub_key: PublicKey::Ecdsa(
    //             HexBinary::from_hex(
    //                 "037286a4f1177bea06c8e15cf6ec3df0b7747a01ac2329ca2999dfd74eff599028",
    //             )
    //                 .unwrap(),
    //         ),
    //     };
    //     let signature = Signature::Ecdsa(
    //         HexBinary::from_hex("ef5ce016a4beed7e11761e5831805e962fca3d8901696a61a6ffd3af2b646bdc3740f64643bdb164b8151d1424eb4943d03f71e71816c00726e2d68ee55600c6").unwrap().try_into().unwrap());
    //     let encoded = encode_execute_data(
    //         &command_batch,
    //         Uint256::from(quorum),
    //         vec![(signer, Some(signature))],
    //     );
    //     assert!(encoded.is_ok());
    //     let encoded = encoded.unwrap();
    //     assert_eq!(encoded.len(), approval.to_vec().len());
    //     assert_eq!(encoded.to_vec(), approval.to_vec());
    // }

    #[test]
    fn test_uint256_to_compact_vec() {
        assert_eq!(
            Vec::<u8>::new(),
            uint256_to_compact_vec(Uint256::from(0u128))
        );
        assert_eq!([1].to_vec(), uint256_to_compact_vec(Uint256::from(1u128)));
        assert_eq!(
            [255].to_vec(),
            uint256_to_compact_vec(Uint256::from(u8::MAX))
        );
        assert_eq!(
            [255, 255].to_vec(),
            uint256_to_compact_vec(Uint256::from(u16::MAX))
        );
        assert_eq!(
            [255, 255, 255, 255].to_vec(),
            uint256_to_compact_vec(Uint256::from(u32::MAX))
        );
        assert_eq!(
            [255, 255, 255, 255, 255, 255, 255, 255].to_vec(),
            uint256_to_compact_vec(Uint256::from(u64::MAX))
        );
        assert_eq!(
            [255].repeat(32).to_vec(),
            uint256_to_compact_vec(Uint256::MAX)
        );
    }

    #[test]
    fn test_make_command_id() {
        assert_eq!([0; 32], make_command_id(&HexBinary::from(vec![0; 32])));
    }

    #[test]
    #[should_panic]
    fn test_make_command_id_fails_too_large() {
        make_command_id(&HexBinary::from(vec![0; 30]));
    }
}
