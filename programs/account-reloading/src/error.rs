use anchor_lang::prelude::*;

#[error_code]
pub enum ReloadError {
    #[msg("Counter value mismatch - stale data detected")]
    StaleData,
}
