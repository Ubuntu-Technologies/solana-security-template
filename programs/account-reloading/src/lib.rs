//! Account Reloading - Anchor Program
//!
//! Demonstrates the vulnerability when account state isn't refreshed after CPI.
//! After a CPI modifies an account, the calling program's deserialized copy
//! becomes stale and doesn't reflect the updated state.
//!
//! VULNERABILITY: Using stale account data after CPI leads to incorrect logic.

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

declare_id!("GBMScyniY2yFUdFQRyBQ9QyHD7qUmJQZmvwJvhbSavG9");

#[program]
pub mod account_reloading {
    use super::*;

    /// Initialize a counter account
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        ctx.accounts.initialize(&ctx.bumps)
    }

    /// Increment the counter (simulates external program CPI)
    pub fn increment(ctx: Context<Increment>) -> Result<()> {
        ctx.accounts.increment()
    }

    /// VULNERABLE: Double increment without reload
    /// After first CPI, counter.count is stale - second operation uses old value
    pub fn vulnerable_double_increment(ctx: Context<VulnerableDoubleIncrement>) -> Result<()> {
        ctx.accounts.double_increment()
    }

    /// SECURE: Double increment with proper reload after CPI
    pub fn secure_double_increment(ctx: Context<SecureDoubleIncrement>) -> Result<()> {
        ctx.accounts.double_increment()
    }
}
