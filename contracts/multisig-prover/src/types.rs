use axelar_wasm_std::{Participant, Snapshot};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{from_binary, HexBinary, StdResult};
use cw_storage_plus::{Key, KeyDeserialize, PrimaryKey};
use multisig::{key::PublicKey, worker_set::WorkerSet};
use router_api::CrossChainId;
use sha3::{Digest, Keccak256};

#[cw_serde]
pub struct BatchId(HexBinary);

impl From<HexBinary> for BatchId {
    fn from(id: HexBinary) -> Self {
        Self(id)
    }
}

impl From<&[u8]> for BatchId {
    fn from(id: &[u8]) -> Self {
        Self(id.into())
    }
}

impl<'a> PrimaryKey<'a> for BatchId {
    type Prefix = ();
    type SubPrefix = ();
    type Suffix = BatchId;
    type SuperSuffix = BatchId;

    fn key(&self) -> Vec<Key> {
        vec![Key::Ref(self.0.as_slice())]
    }
}

impl KeyDeserialize for BatchId {
    type Output = BatchId;

    fn from_vec(value: Vec<u8>) -> StdResult<Self::Output> {
        Ok(from_binary(&value.into()).expect("violated invariant: BatchID is not deserializable"))
    }
}

impl BatchId {
    pub fn new(message_ids: &[CrossChainId], new_worker_set: Option<WorkerSet>) -> BatchId {
        let mut message_ids = message_ids
            .iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>();
        message_ids.sort();

        if let Some(new_worker_set) = new_worker_set {
            message_ids.push(new_worker_set.hash().to_string())
        }
        Keccak256::digest(message_ids.join(",")).as_slice().into()
    }
}

pub struct WorkersInfo {
    pub snapshot: Snapshot,
    pub pubkeys_by_participant: Vec<(Participant, PublicKey)>,
}
