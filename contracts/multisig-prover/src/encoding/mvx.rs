use cosmwasm_std::{HexBinary, Uint256};
use crate::{
    error::ContractError,
    state::WorkerSet,
    types::{CommandBatch, Operator},
};

use multiversx_sc_codec::top_encode_to_vec_u8;

pub fn command_params(
    source_chain: String,
    source_address: String,
    destination_address: String,
    payload_hash: &[u8; 32],
) -> Result<HexBinary, ContractError> {
    // TODO: We assume here that the bech32 address was converted to 32 bytes HEX when a cross-chain call was initiated. Is this right?
    let destination_address = <[u8; 32]>::try_from(
        HexBinary::from_hex(&destination_address)?.to_vec(),
    )
        .map_err(|_| ContractError::InvalidMessage {
            reason: format!(
                "destination_address is not a valid Mvx address: {}",
                destination_address
            ),
        })?;

    Ok(top_encode_to_vec_u8(&(
        source_chain,
        source_address,
        destination_address,
        payload_hash
    ))
        .expect("couldn't serialize command as mvx")
        .into())
}
