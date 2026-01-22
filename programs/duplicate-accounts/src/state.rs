use anchor_lang::prelude::*;

#[account]
pub struct UserBalance {
    pub owner: Pubkey,
    pub balance: u64,
    pub bump: u8,
}
