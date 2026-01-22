use anchor_lang::prelude::*;

#[account]
pub struct AuthConfig {
    pub authority: Pubkey,
    pub pending_authority: Option<Pubkey>,
    pub bump: u8,
}
