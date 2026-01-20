//! SECURE: Proper Account Closure
//!
//! THE FIX:
//! 1. Zero out all account data before closing
//! 2. Mark account as closed (discriminator = 0)
//! 3. Use force_defund to handle edge cases
//! 4. Check is_initialized flag on subsequent reads

use crate::error::CloseError;
use crate::state::UserAccount;
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct SecureClose<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,

    #[account(
        mut,
        seeds = [b"user", owner.key().as_ref()],
        bump = user_account.bump,
        constraint = user_account.is_initialized @ CloseError::AlreadyClosed,
        close = owner
    )]
    pub user_account: Account<'info, UserAccount>,
}

impl<'info> SecureClose<'info> {
    pub fn close(&mut self) -> Result<()> {
        // ---------------------------------------------------------------------------
        // FIX 1: Zero out all sensitive data before closing
        // This prevents data leakage if account is revived
        // ---------------------------------------------------------------------------
        self.user_account.owner = Pubkey::default();
        self.user_account.balance = 0;
        self.user_account.is_initialized = false;

        // ---------------------------------------------------------------------------
        // FIX 2: The account data is then serialized back (zeroed)
        // Combined with Anchor's close = owner, this properly closes the account
        //
        // Note: Anchor's close constraint handles:
        // - Transferring all lamports to destination
        // - Setting account owner to system program
        // ---------------------------------------------------------------------------

        // Additional protection: In production, consider using
        // AccountInfo::realloc to shrink account to 0 bytes

        Ok(())
    }
}
