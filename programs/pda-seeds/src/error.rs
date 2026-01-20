//! Error definitions for PDA Seeds program

use anchor_lang::prelude::*;

#[error_code]
pub enum PdaError {
    #[msg("Unauthorized access")]
    Unauthorized,
    #[msg("Invalid PDA derivation")]
    InvalidPda,
}
