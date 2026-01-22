//! Duplicate Mutable Accounts - Anchor Program
//!
//! Demonstrates the vulnerability when the same account is passed twice
//! as different mutable parameters, causing unexpected state changes.
//!
//! VULNERABILITY: If from_account and to_account are the same,
//! credits and debits cancel out unexpectedly.

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

declare_id!("BgxHghQVFFavSL6VBpJ6eoKec1yBoAYVS24EfGXHXxTz");

#[program]
pub mod duplicate_accounts {
    use super::*;

    /// Initialize a user balance account
    pub fn initialize(ctx: Context<Initialize>, initial_balance: u64) -> Result<()> {
        ctx.accounts.initialize(&ctx.bumps, initial_balance)
    }

    /// VULNERABLE: Transfer between accounts without duplicate check
    /// If from == to, balance stays the same but event shows transfer happened
    pub fn vulnerable_transfer(ctx: Context<VulnerableTransfer>, amount: u64) -> Result<()> {
        ctx.accounts.transfer(amount)
    }

    /// SECURE: Transfer with duplicate account protection
    pub fn secure_transfer(ctx: Context<SecureTransfer>, amount: u64) -> Result<()> {
        ctx.accounts.transfer(amount)
    }
}
