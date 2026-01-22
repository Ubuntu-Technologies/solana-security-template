use anchor_lang::prelude::*;

use crate::error::TransferError;
use crate::state::UserBalance;

// ---------------------------------------------------------------------------
// SECURE: Duplicate Account Protection
// ---------------------------------------------------------------------------
// FIX: Add constraint ensuring from_account != to_account.
// This prevents the duplicate mutable accounts attack.
// ---------------------------------------------------------------------------

#[derive(Accounts)]
pub struct SecureTransfer<'info> {
    pub authority: Signer<'info>,

    #[account(
        mut,
        seeds = [b"balance", from_account.owner.as_ref()],
        bump = from_account.bump,
    )]
    pub from_account: Account<'info, UserBalance>,

    #[account(
        mut,
        // SECURE: Constraint ensures accounts are different
        constraint = from_account.key() != to_account.key() @ TransferError::DuplicateAccounts
    )]
    pub to_account: Account<'info, UserBalance>,
}

impl<'info> SecureTransfer<'info> {
    /// Transfer tokens between accounts.
    /// SAFE: Constraint prevents duplicate accounts.
    pub fn transfer(&mut self, amount: u64) -> Result<()> {
        // Check sufficient balance
        require!(
            self.from_account.balance >= amount,
            TransferError::InsufficientBalance
        );

        // Safe to proceed - we know accounts are different
        self.from_account.balance = self
            .from_account
            .balance
            .checked_sub(amount)
            .ok_or(TransferError::InsufficientBalance)?;

        self.to_account.balance = self
            .to_account
            .balance
            .checked_add(amount)
            .ok_or(TransferError::InsufficientBalance)?;

        Ok(())
    }
}
