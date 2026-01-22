//! Authority Transfer - Anchor Program
//!
//! Demonstrates vulnerabilities in admin/authority transfer functionality.
//! Improper transfer logic can lead to loss of control or unauthorized takeover.
//!
//! VULNERABILITY: Missing validation in authority transfer allows attackers
//! to take control of protocol.

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

declare_id!("3APkTen4wwfvKAyjrwxCaCWVKEkwagJd5cXwJeFkefVS");

#[program]
pub mod authority_transfer {
    use super::*;

    /// Initialize config with initial authority
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        ctx.accounts.initialize(&ctx.bumps)
    }

    /// VULNERABLE: Direct authority transfer - no confirmation required
    /// Attacker can set authority to their address if they exploit another bug
    pub fn vulnerable_transfer(
        ctx: Context<VulnerableTransfer>,
        new_authority: Pubkey,
    ) -> Result<()> {
        ctx.accounts.transfer(new_authority)
    }

    /// SECURE: Two-step authority transfer
    /// Step 1: Current authority proposes new authority
    pub fn propose_authority(ctx: Context<ProposeAuthority>, new_authority: Pubkey) -> Result<()> {
        ctx.accounts.propose(new_authority)
    }

    /// SECURE: Two-step authority transfer
    /// Step 2: New authority must accept (proves they control the key)
    pub fn accept_authority(ctx: Context<AcceptAuthority>) -> Result<()> {
        ctx.accounts.accept()
    }
}
