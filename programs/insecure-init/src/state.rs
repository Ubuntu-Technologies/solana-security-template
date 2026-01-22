use anchor_lang::prelude::*;

#[account]
pub struct Config {
    pub admin: Pubkey,
    pub is_initialized: bool,
    pub bump: u8,
}

impl Config {
    pub const SIZE: usize = 8 + 32 + 1 + 1; // discriminator + pubkey + bool + bump
}
