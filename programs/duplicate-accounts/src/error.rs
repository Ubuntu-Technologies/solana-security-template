use anchor_lang::prelude::*;

#[error_code]
pub enum TransferError {
    #[msg("Insufficient balance for transfer")]
    InsufficientBalance,
    #[msg("Cannot transfer to same account")]
    DuplicateAccounts,
}
