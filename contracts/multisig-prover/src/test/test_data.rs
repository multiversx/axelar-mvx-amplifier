use std::collections::BTreeMap;

use axelar_wasm_std::{nonempty, MajorityThreshold, Threshold};
use connection_router::state::Message;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, HexBinary, Uint256, Uint64};
use multisig::{
    key::{KeyType, PublicKey, Signature},
    msg::Signer,
    worker_set::WorkerSet,
};

pub fn new_worker_set() -> WorkerSet {
    let signers = vec![
        Signer {
            address: Addr::unchecked("axelarvaloper1x86a8prx97ekkqej2x636utrdu23y8wupp9gk5"),
            weight: Uint256::from(10u128),
            pub_key: PublicKey::Ecdsa(
                HexBinary::from_hex(
                    "03d123ce370b163acd576be0e32e436bb7e63262769881d35fa3573943bf6c6f81",
                )
                .unwrap(),
            ),
        },
        Signer {
            address: Addr::unchecked("axelarvaloper1ff675m593vve8yh82lzhdnqfpu7m23cxstr6h4"),
            weight: Uint256::from(10u128),
            pub_key: PublicKey::Ecdsa(
                HexBinary::from_hex(
                    "03c6ddb0fcee7b528da1ef3c9eed8d51eeacd7cc28a8baa25c33037c5562faa6e4",
                )
                .unwrap(),
            ),
        },
        Signer {
            address: Addr::unchecked("axelarvaloper12cwre2gdhyytc3p97z9autzg27hmu4gfzz4rxc"),
            weight: Uint256::from(10u128),
            pub_key: PublicKey::Ecdsa(
                HexBinary::from_hex(
                    "0274b5d2a4c55d7edbbf9cc210c4d25adbb6194d6b444816235c82984bee518255",
                )
                .unwrap(),
            ),
        },
        Signer {
            address: Addr::unchecked("axelarvaloper1vs9rdplntrf7ceqdkznjmanrr59qcpjq6le0yw"),
            weight: Uint256::from(10u128),
            pub_key: PublicKey::Ecdsa(
                HexBinary::from_hex(
                    "02a670f57de55b8b39b4cb051e178ca8fb3fe3a78cdde7f8238baf5e6ce1893185",
                )
                .unwrap(),
            ),
        },
        Signer {
            address: Addr::unchecked("axelarvaloper1hz0slkejw96dukw87fztjkvwjdpcu20jewg6mw"),
            weight: Uint256::from(10u128),
            pub_key: PublicKey::Ecdsa(
                HexBinary::from_hex(
                    "028584592624e742ba154c02df4c0b06e4e8a957ba081083ea9fe5309492aa6c7b",
                )
                .unwrap(),
            ),
        },
    ];

    let mut btree_signers = BTreeMap::new();
    for signer in signers {
        btree_signers.insert(signer.address.clone().to_string(), signer);
    }

    WorkerSet {
        signers: btree_signers,
        threshold: Uint256::from(30u128),
        created_at: 1,
    }
}

pub fn new_signers_ed25519() -> Vec<Signer> {
    vec![
        Signer {
            address: Addr::unchecked("axelarvaloper1x86a8prx97ekkqej2x636utrdu23y8wupp9gk5"),
            weight: Uint256::from(10u128),
            pub_key: PublicKey::Ed25519(
                HexBinary::from_hex(
                    "ca5b4abdf9eec1f8e2d12c187d41ddd054c81979cae9e8ee9f4ecab901cac5b6",
                )
                    .unwrap(),
            ),
        },
        Signer {
            address: Addr::unchecked("axelarvaloper1ff675m593vve8yh82lzhdnqfpu7m23cxstr6h4"),
            weight: Uint256::from(10u128),
            pub_key: PublicKey::Ed25519(
                HexBinary::from_hex(
                    "ef637606f3144ee46343ba4a25c261b5c400ade88528e876f3deababa22a4449",
                )
                    .unwrap(),
            ),
        },
    ]
}

pub fn new_worker_set_ed25519() -> WorkerSet {
    let signers = new_signers_ed25519();

    let mut btree_signers = BTreeMap::new();
    for signer in signers {
        btree_signers.insert(signer.address.clone().to_string(), signer);
    }

    WorkerSet {
        signers: btree_signers,
        threshold: Uint256::from(20u128),
        created_at: 1,
    }
}

pub fn messages() -> Vec<Message> {
    vec![Message {
        cc_id: "ganache-1:0xff822c88807859ff226b58e24f24974a70f04b9442501ae38fd665b3c68f3834:0"
            .parse()
            .unwrap(),
        source_address: "0x52444f1835Adc02086c37Cb226561605e2E1699b"
            .parse()
            .unwrap(),
        destination_address: "0xA4f10f76B86E01B98daF66A3d02a65e14adb0767"
            .parse()
            .unwrap(),
        destination_chain: "ganache-0".parse().unwrap(),
        payload_hash: HexBinary::from_hex(
            "8c3685dc41c2eca11426f8035742fb97ea9f14931152670a5703f18fe8b392f0",
        )
        .unwrap()
        .to_array::<32>()
        .unwrap(),
    }]
}

pub fn destination_chain_id() -> Uint256 {
    Uint256::from(1337u128)
}

pub fn encoded_data_with_operator_transfer() -> HexBinary {
    HexBinary::from_hex("0000000000000000000000000000000000000000000000000000000000000539000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000001400000000000000000000000000000000000000000000000000000000000000001db7362a425610350d24692e913a3ac1b709565274875883962b48d1d3ed43e5c0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000147472616e736665724f70657261746f72736869700000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000001e000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000120000000000000000000000000000000000000000000000000000000000000001e00000000000000000000000000000000000000000000000000000000000000050000000000000000000000000249c31dd0eacb2d73bbe5a0513416cd3888cb5b0000000000000000000000001ae3758c032ae8ebf6f075bb5b6ff6129b56e632000000000000000000000000adb32b50b13f962d302619111de6a1020fbd55f7000000000000000000000000defab04334a82fdea683bca3617c33bc469d4cc9000000000000000000000000e6857cf86038ba741e64ce0d3c883a26a7d3cb460000000000000000000000000000000000000000000000000000000000000005000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000a").unwrap()
}

pub fn chain_id_operator_transfer() -> Uint256 {
    Uint256::from(1337u128)
}

pub fn encoded_data() -> HexBinary {
    HexBinary::from_hex(
        "0000000000000000000000000000000000000000000000000000000000000539000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000000013ee2f8af2201994e3518c9ce6848774785c2eef3bdbf9f954899497616dd59af000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000013617070726f7665436f6e747261637443616c6c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000a4f10f76b86e01b98daf66a3d02a65e14adb07678c3685dc41c2eca11426f8035742fb97ea9f14931152670a5703f18fe8b392f00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000967616e616368652d310000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a30783532343434663138333541646330323038366333374362323236353631363035653245313639396200000000000000000000000000000000000000000000").unwrap()
}

pub fn msg_to_sign() -> HexBinary {
    HexBinary::from_hex("7140b89fc7207cd96a262ef8e3f9301cdd72549e01894070ce5a7f2d4096819f").unwrap()
}

pub fn encoded_proof() -> HexBinary {
    HexBinary::from_hex("0000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000500000000000000000000000011c67adfe52a3782bd518294188c4aafaaf6cdeb0000000000000000000000004905fd2e40b1a037256e32fe1e4bca41ae510d730000000000000000000000004ef5c8d81b6417fa80c320b5fc1d3900506dff540000000000000000000000006c51eec96bf0a8ec799cdd0bbcb4512f8334afe8000000000000000000000000a6e7b3b7a1af4103f540d05776f7dd200210201f0000000000000000000000000000000000000000000000000000000000000005000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000001600000000000000000000000000000000000000000000000000000000000000041eff382a60ef4d917ae0bcbd58ab121fbd7bd53b777773bf1da298d3701565a3379a5b741f881ad739e651a544f2331c085c482857856201c49328ae9ba65cf131c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000041301ff4127c1c5a865732776769c6227e4978a1c4567bc1d2926cd798422f1f507b10989e173c6ebc23334eb7e3c713e940369c418061d5cad1173882f35dc43d1b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000041c55581edbf0401d0cd3495522323e45d4521312dafdedf39b4adc8085a3842c74f13c055b72d12ec3afc1e8f9c37b5f660fbefb38165dbe61090923865e158271b00000000000000000000000000000000000000000000000000000000000000").unwrap()
}

pub fn execute_data() -> HexBinary {
    HexBinary::from_hex("09c5eabe000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000007600000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000034000000000000000000000000000000000000000000000000000000000000002e00000000000000000000000000000000000000000000000000000000000000539000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000000013ee2f8af2201994e3518c9ce6848774785c2eef3bdbf9f954899497616dd59af000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000013617070726f7665436f6e747261637443616c6c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000a4f10f76b86e01b98daf66a3d02a65e14adb07678c3685dc41c2eca11426f8035742fb97ea9f14931152670a5703f18fe8b392f00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000967616e616368652d310000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a3078353234343466313833354164633032303836633337436232323635363136303565324531363939620000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000500000000000000000000000011c67adfe52a3782bd518294188c4aafaaf6cdeb0000000000000000000000004905fd2e40b1a037256e32fe1e4bca41ae510d730000000000000000000000004ef5c8d81b6417fa80c320b5fc1d3900506dff540000000000000000000000006c51eec96bf0a8ec799cdd0bbcb4512f8334afe8000000000000000000000000a6e7b3b7a1af4103f540d05776f7dd200210201f0000000000000000000000000000000000000000000000000000000000000005000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000001600000000000000000000000000000000000000000000000000000000000000041eff382a60ef4d917ae0bcbd58ab121fbd7bd53b777773bf1da298d3701565a3379a5b741f881ad739e651a544f2331c085c482857856201c49328ae9ba65cf131c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000041301ff4127c1c5a865732776769c6227e4978a1c4567bc1d2926cd798422f1f507b10989e173c6ebc23334eb7e3c713e940369c418061d5cad1173882f35dc43d1b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000041c55581edbf0401d0cd3495522323e45d4521312dafdedf39b4adc8085a3842c74f13c055b72d12ec3afc1e8f9c37b5f660fbefb38165dbe61090923865e158271b00000000000000000000000000000000000000000000000000000000000000").unwrap()
}

pub fn threshold() -> MajorityThreshold {
    let numerator: nonempty::Uint64 = Uint64::from(2u8).try_into().unwrap();
    let denominator: nonempty::Uint64 = Uint64::from(3u8).try_into().unwrap();
    Threshold::try_from((numerator, denominator))
        .unwrap()
        .try_into()
        .unwrap()
}

#[cw_serde]
pub struct TestOperator {
    pub address: Addr,
    pub pub_key: multisig::key::PublicKey,
    pub operator: HexBinary,
    pub weight: Uint256,
    pub signature: Option<Signature>,
}

pub fn operators() -> Vec<TestOperator> {
    [
        (
            "axelar1up3vvhxg4swh2lfeh8n84dat86j6hmgz20d6d3",
            "0312474390012cfbb621c91295dae42b11daaceffbcb7136045c86537a7b37042c",
            "6C51eec96bf0a8ec799cdD0Bbcb4512f8334Afe8",
            1u128,
            None,
        ),
        (
            "axelar10ad5vqhuw2jgp8x6hf59qjjejlna2nh4sfsklc",
            "0277b844fb49bf9b5838dc15d79f3c6c7701eb2e0ab066d4aa63ce162b08718d37",
            "11C67adfe52a3782bd518294188C4AAfaaF6cDeb",
            1u128,
            Some("eff382a60ef4d917ae0bcbd58ab121fbd7bd53b777773bf1da298d3701565a3379a5b741f881ad739e651a544f2331c085c482857856201c49328ae9ba65cf13"),
        ),
        (
            "axelar14g0tmk5ldxxdqtl0utl69ck43cpcvd0ay4lfyt",
            "03a54c7ad1621b57803bc5bcfe826b713bf5c5a15906ccd08f271d58992bee71d6",
            "4905FD2e40B1A037256e32fe1e4BCa41AE510d73",
            1u128,
            Some("301ff4127c1c5a865732776769c6227e4978a1c4567bc1d2926cd798422f1f507b10989e173c6ebc23334eb7e3c713e940369c418061d5cad1173882f35dc43d"),
        ),
        (
            "axelar1gwd8wd3qkapk8pnwdu4cchah2sjjws6lx694r6",
            "033a9726a6e2fdc308089c6cab1e6fda2e2bddeb2bcf800990e5fd2c05a270c9df",
            "a6E7b3b7A1AF4103F540D05776F7dd200210201F",
            1u128,
            Some("c55581edbf0401d0cd3495522323e45d4521312dafdedf39b4adc8085a3842c74f13c055b72d12ec3afc1e8f9c37b5f660fbefb38165dbe61090923865e15827"),
        ),
        (
            "axelar1fcrwupthhxm6zsd7kw00w2fk530p6wtt8mj92l",
            "02d1e0cff63aa3e7988e4070242fa37871a9abc79ecf851cce9877297d1316a090",
            "4ef5C8d81b6417fa80c320B5Fc1D3900506dFf54",
            1u128,
            None,
        ),
    ]
    .into_iter()
    .map(
        |(address, pub_key, operator, weight, signature)| TestOperator {
            address: Addr::unchecked(address),
            pub_key: (KeyType::Ecdsa, HexBinary::from_hex(pub_key).unwrap())
                .try_into()
                .unwrap(),
            operator: HexBinary::from_hex(operator).unwrap(),
            weight: Uint256::from(weight),
            signature: signature.map(|sig| {
                (KeyType::Ecdsa, HexBinary::from_hex(sig).unwrap())
                    .try_into()
                    .unwrap()
            }),
        },
    )
    .collect()
}

pub fn quorum() -> Uint256 {
    3u128.into()
}
