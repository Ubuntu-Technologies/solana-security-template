use anchor_lang::prelude::*;

use crate::error::InitError;
use crate::state::Config;

// ---------------------------------------------------------------------------
// SECURE: Proper Initialization with Guard
// ---------------------------------------------------------------------------
// FIX: Use `init` instead of `init_if_needed`, OR check is_initialized flag.
// This prevents re-initialization attacks.
// ---------------------------------------------------------------------------

#[derive(Accounts)]
pub struct SecureInitialize<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(
        init,  // SECURE: Will fail if account already exists
        payer = payer,
        space = Config::SIZE,
        seeds = [b"secure_config"],
        bump
    )]
    pub config: Account<'info, Config>,

    pub system_program: Program<'info, System>,
}

impl<'info> SecureInitialize<'info> {
    /// Initialize config - only works once due to `init` constraint.
    /// SAFE: Anchor's `init` fails if account has non-zero lamports.
    pub fn initialize(&mut self, admin: Pubkey) -> Result<()> {
        // With `init`, this can only be called once
        self.config.admin = admin;
        self.config.is_initialized = true;
        self.config.bump = 0; // Will be set by Anchor

        Ok(())
    }
}

// Alternative secure pattern using init_if_needed with explicit check:
#[derive(Accounts)]
pub struct SecureInitializeAlt<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(
        init_if_needed,
        payer = payer,
        space = Config::SIZE,
        seeds = [b"alt_config"],
        bump
    )]
    pub config: Account<'info, Config>,

    pub system_program: Program<'info, System>,
}

impl<'info> SecureInitializeAlt<'info> {
    /// Initialize with explicit is_initialized check.
    pub fn initialize(&mut self, admin: Pubkey) -> Result<()> {
        // SECURE: Check if already initialized
        require!(!self.config.is_initialized, InitError::AlreadyInitialized);

        self.config.admin = admin;
        self.config.is_initialized = true;

        Ok(())
    }
}
