use anchor_lang::prelude::*;

#[error_code]
pub enum PoolError {
    #[msg("Math overflow detected")]
    MathOverflow,

    #[msg("Slippage exceeded: output less than minimum")]
    SlippageExceeded,

    #[msg("Invalid amount: cannot be zero")]
    InvalidAmount,

    #[msg("Insufficient reserves in pool")]
    InsufficientReserves,
}
