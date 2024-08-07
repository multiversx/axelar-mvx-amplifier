use cosmwasm_std::StdError;
use error_stack::{Context, Report};
use report::LoggableError;
use thiserror::Error;

use crate::permission_control;

/// This error is supposed to be the top-level error type our contracts return to the cosmwasm module.
/// Ideally, we would like to return an error-stack [Report] directly,
/// but it won't show all necessary information (namely attachments) in the error message, and many places also return an [StdError].
/// To this end, reports get converted into [LoggableError] and this [ContractError] type unifies [LoggableError] and [StdError],
/// so we can return both to cosmwasm.
#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error(transparent)]
    Std(#[from] StdError),
    #[error(transparent)]
    Structured(#[from] LoggableError),
    #[error(transparent)]
    Unauthorized(#[from] permission_control::Error),
    #[error(transparent)]
    WrongVersion(#[from] cw2::VersionError),
}

impl<T> From<Report<T>> for ContractError
where
    T: Context,
{
    fn from(report: Report<T>) -> Self {
        ContractError::Structured(LoggableError::from(&report))
    }
}

/// Merges two error reports into one. If the result is Ok, the added error is returned.
pub fn extend_err<T, E: Context>(
    result: error_stack::Result<T, E>,
    added_error: Report<E>,
) -> error_stack::Result<T, E> {
    if let Err(mut base_err) = result {
        base_err.extend_one(added_error);
        Err(base_err)
    } else {
        Err(added_error)
    }
}
