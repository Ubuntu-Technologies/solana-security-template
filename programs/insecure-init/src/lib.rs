//! Insecure Initialization - Anchor Program
//!
//! Demonstrates the vulnerability when program state can be re-initialized,
//! allowing attackers to overwrite critical configuration.
//!
//! VULNERABILITY: Missing is_initialized check allows re-initialization.

#![allow(unexpected_cfgs)]

use anchor_lang::prelude::*;

pub mod error;
pub mod secure;
pub mod state;
pub mod vulnerable;

use secure::*;
use vulnerable::*;

declare_id!("4jYJ4EhViLDVKAswFSX84LnFdb8FetpAPWsqxyXaa5cK");

#[program]
pub mod insecure_init {
    use super::*;

    /// VULNERABLE: Initialize config without checking if already initialized
    /// Attacker can reinitialize and become admin
    pub fn vulnerable_initialize(ctx: Context<VulnerableInitialize>, admin: Pubkey) -> Result<()> {
        ctx.accounts.initialize(admin)
    }

    /// SECURE: Initialize with proper is_initialized guard
    pub fn secure_initialize(ctx: Context<SecureInitialize>, admin: Pubkey) -> Result<()> {
        ctx.accounts.initialize(admin)
    }

    /// Admin action that requires authorization
    pub fn admin_action(ctx: Context<AdminAction>) -> Result<()> {
        msg!("Admin action executed by: {}", ctx.accounts.admin.key());
        Ok(())
    }
}

#[derive(Accounts)]
pub struct AdminAction<'info> {
    #[account(
        constraint = config.admin == admin.key() @ error::InitError::Unauthorized
    )]
    pub config: Account<'info, state::Config>,

    pub admin: Signer<'info>,
}
