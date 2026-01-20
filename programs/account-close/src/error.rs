//! Error definitions for Account Close program

use anchor_lang::prelude::*;

#[error_code]
pub enum CloseError {
    #[msg("Account still has remaining balance")]
    HasBalance,
    #[msg("Account already closed")]
    AlreadyClosed,
}
