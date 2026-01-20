//! Secure AMM - Properly Implemented with Security Best Practices
//!
//! Compare with buggy-amm to see the vulnerabilities fixed here.

use anchor_lang::prelude::*;

pub mod instructions;
pub mod state;

use instructions::*;

declare_id!("SecureAMM1111111111111111111111111111111111");

#[program]
pub mod secure_amm {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>, seed: u64, fee: u16) -> Result<()> {
        instructions::initialize::handler(ctx, seed, fee)
    }

    pub fn deposit(ctx: Context<Deposit>, amount: u64, max_x: u64, max_y: u64) -> Result<()> {
        instructions::deposit::handler(ctx, amount, max_x, max_y)
    }

    pub fn swap(ctx: Context<Swap>, amount_in: u64, min_out: u64) -> Result<()> {
        instructions::swap::handler(ctx, amount_in, min_out)
    }

    pub fn withdraw(ctx: Context<Withdraw>, lp_amount: u64, min_x: u64, min_y: u64) -> Result<()> {
        instructions::withdraw::handler(ctx, lp_amount, min_x, min_y)
    }
}
