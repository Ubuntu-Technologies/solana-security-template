use anchor_lang::prelude::*;

#[error_code]
pub enum AuthError {
    #[msg("No pending authority to accept")]
    NoPendingAuthority,
    #[msg("Not the pending authority")]
    NotPendingAuthority,
    #[msg("Cannot transfer to zero address")]
    ZeroAddress,
}
