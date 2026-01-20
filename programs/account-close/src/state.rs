//! State definitions for Account Close program

use anchor_lang::prelude::*;

/// User account that stores balance data
#[account]
#[derive(InitSpace)]
pub struct UserAccount {
    pub owner: Pubkey,
    pub balance: u64,
    pub is_initialized: bool,
    pub bump: u8,
}
