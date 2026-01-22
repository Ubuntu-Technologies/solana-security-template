//! SECURE: Strong PDA Seeds
//!
//! THE FIX:
//! 1. Use multiple seeds including a random/unique nonce
//! 2. Store and verify the canonical bump seed
//! 3. Include program-specific prefix in seeds

use crate::error::PdaError;
use crate::state::StrongUserAccount;
use anchor_lang::prelude::*;

#[derive(Accounts)]
#[instruction(nonce: u64)]
pub struct SecureCreateUser<'info> {
    #[account(mut)]
    pub user: Signer<'info>,

    // ---------------------------------------------------------------------------
    // FIX: Seeds include multiple components:
    // - Static prefix ("user_v1") - prevents cross-program collision
    // - User pubkey - ties to specific user
    // - Nonce - adds randomness/uniqueness
    // ---------------------------------------------------------------------------
    #[account(
        init,
        payer = user,
        space = 8 + StrongUserAccount::INIT_SPACE,
        seeds = [
            b"user_v1",           // Program-specific prefix
            user.key().as_ref(), // User identity
            &nonce.to_le_bytes() // Unique nonce
        ],
        bump
    )]
    pub user_account: Account<'info, StrongUserAccount>,

    pub system_program: Program<'info, System>,
}

impl<'info> SecureCreateUser<'info> {
    pub fn create_user(&mut self, bumps: &SecureCreateUserBumps, nonce: u64) -> Result<()> {
        self.user_account.owner = self.user.key();
        self.user_account.nonce = nonce;
        self.user_account.data = 0;
        self.user_account.bump = bumps.user_account;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct SecureUpdate<'info> {
    pub user: Signer<'info>,

    // ---------------------------------------------------------------------------
    // FIX: Verify stored bump is canonical
    // This ensures the PDA was properly initialized and not spoofed
    // ---------------------------------------------------------------------------
    #[account(
        mut,
        seeds = [
            b"user_v1",
            user.key().as_ref(),
            &user_account.nonce.to_le_bytes()
        ],
        bump = user_account.bump,  // SECURE: Use stored canonical bump
        constraint = user_account.owner == user.key() @ PdaError::Unauthorized
    )]
    pub user_account: Account<'info, StrongUserAccount>,
}

impl<'info> SecureUpdate<'info> {
    pub fn update(&mut self, data: u64) -> Result<()> {
        self.user_account.data = data;
        Ok(())
    }
}
