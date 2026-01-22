use anchor_lang::prelude::*;

use crate::error::TransferError;
use crate::state::UserBalance;

// ---------------------------------------------------------------------------
// VULNERABILITY: Duplicate Mutable Accounts
// ---------------------------------------------------------------------------
// No check that from_account and to_account are different.
// If same account is passed twice:
//   - Debit from_account: balance becomes 50
//   - Credit to_account (same): balance becomes 150
//   - Net effect: +100 out of nowhere!
// ---------------------------------------------------------------------------

#[derive(Accounts)]
pub struct VulnerableTransfer<'info> {
    pub authority: Signer<'info>,

    #[account(
        mut,
        seeds = [b"balance", from_account.owner.as_ref()],
        bump = from_account.bump,
    )]
    pub from_account: Account<'info, UserBalance>,

    #[account(mut)]
    /// CHECK: VULNERABLE - No constraint preventing this from being same as from_account
    pub to_account: Account<'info, UserBalance>,
}

impl<'info> VulnerableTransfer<'info> {
    /// Transfer tokens between accounts.
    /// DANGER: If from_account == to_account, unexpected behavior!
    pub fn transfer(&mut self, amount: u64) -> Result<()> {
        // Check sufficient balance
        require!(
            self.from_account.balance >= amount,
            TransferError::InsufficientBalance
        );

        // VULNERABLE: No check that accounts are different!
        // Debit source
        self.from_account.balance = self
            .from_account
            .balance
            .checked_sub(amount)
            .ok_or(TransferError::InsufficientBalance)?;

        // Credit destination
        self.to_account.balance = self
            .to_account
            .balance
            .checked_add(amount)
            .ok_or(TransferError::InsufficientBalance)?;

        Ok(())
    }
}
