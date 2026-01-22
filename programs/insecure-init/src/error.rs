use anchor_lang::prelude::*;

#[error_code]
pub enum InitError {
    #[msg("Account already initialized")]
    AlreadyInitialized,
    #[msg("Unauthorized - not admin")]
    Unauthorized,
}
