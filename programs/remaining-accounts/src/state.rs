use anchor_lang::prelude::*;

#[account]
pub struct BatchConfig {
    pub authority: Pubkey,
    pub bump: u8,
}

/// Structure for validated reward recipient
#[account]
pub struct RewardRecipient {
    pub owner: Pubkey,
    pub is_eligible: bool,
    pub bump: u8,
}
