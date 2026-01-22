use anchor_lang::prelude::*;

#[error_code]
pub enum BatchError {
    #[msg("Invalid account in remaining_accounts")]
    InvalidAccount,
    #[msg("Account not eligible for rewards")]
    NotEligible,
    #[msg("Account count mismatch with amounts")]
    CountMismatch,
    #[msg("Account not owned by program")]
    InvalidOwner,
}
