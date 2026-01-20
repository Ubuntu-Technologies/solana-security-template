//! State with proper discriminator (Anchor handles this automatically)

use anchor_lang::prelude::*;

/// Pool configuration - Anchor's #[account] macro adds 8-byte discriminator
#[account]
#[derive(InitSpace)]
pub struct Config {
    pub seed: u64,
    pub authority: Option<Pubkey>, // FIX: Optional admin for updates
    pub mint_x: Pubkey,
    pub mint_y: Pubkey,
    pub fee: u16,
    pub locked: bool,
    pub config_bump: u8,
    pub lp_bump: u8,
}
