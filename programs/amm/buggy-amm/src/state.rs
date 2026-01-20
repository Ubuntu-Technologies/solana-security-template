//! State definitions - VULNERABLE: No discriminator for type safety

use anchor_lang::prelude::*;

/// Pool configuration account
/// VULN: No discriminator byte - can be confused with other account types
#[account]
#[derive(InitSpace)]
pub struct Config {
    pub seed: u64,
    pub mint_x: Pubkey,
    pub mint_y: Pubkey,
    pub fee: u16, // basis points
    pub locked: bool,
    pub config_bump: u8,
    pub lp_bump: u8,
}
