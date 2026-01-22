//! Remaining Accounts - Anchor Program
//!
//! Demonstrates the vulnerability when ctx.remaining_accounts are used
//! without proper validation. These accounts bypass Anchor's built-in checks.
//!
//! VULNERABILITY: remaining_accounts are not validated by Anchor constraints.

#![allow(unexpected_cfgs)]

use anchor_lang::prelude::*;

pub mod error;
pub mod initialize;
pub mod secure;
pub mod state;
pub mod vulnerable;

use initialize::*;
use secure::*;
use vulnerable::*;

declare_id!("Eypux1FctAjxFzjEXyP6RGab8brjy2LtBU9dtQThFacP");

#[program]
pub mod remaining_accounts {
    use super::*;

    /// Initialize a batch processor config
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        ctx.accounts.initialize(&ctx.bumps)
    }

    /// VULNERABLE: Process rewards to remaining_accounts without validation
    /// Attacker can pass any accounts and receive rewards
    pub fn vulnerable_batch_reward<'a, 'b, 'c, 'info>(
        ctx: Context<'a, 'b, 'c, 'info, VulnerableBatchReward<'info>>,
        amounts: Vec<u64>,
    ) -> Result<()> {
        ctx.accounts
            .process_rewards(ctx.remaining_accounts, amounts)
    }

    /// SECURE: Process rewards with proper account validation
    pub fn secure_batch_reward<'a, 'b, 'c, 'info>(
        ctx: Context<'a, 'b, 'c, 'info, SecureBatchReward<'info>>,
        amounts: Vec<u64>,
    ) -> Result<()> {
        ctx.accounts
            .process_rewards(ctx.remaining_accounts, amounts)
    }
}
