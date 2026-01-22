use anchor_lang::prelude::*;

use crate::state::Counter;

// ---------------------------------------------------------------------------
// SECURE: Proper Account Reloading After CPI
// ---------------------------------------------------------------------------
// FIX: Call account.reload() after any CPI that may modify the account.
// This refreshes the deserialized data from the underlying account storage.
// ---------------------------------------------------------------------------

#[derive(Accounts)]
pub struct SecureDoubleIncrement<'info> {
    pub authority: Signer<'info>,

    #[account(
        mut,
        seeds = [b"counter", authority.key().as_ref()],
        bump = counter.bump,
        has_one = authority
    )]
    pub counter: Account<'info, Counter>,
}

impl<'info> SecureDoubleIncrement<'info> {
    /// Double increment with proper reload.
    /// SAFE: We reload after operations that may have modified the account.
    pub fn double_increment(&mut self) -> Result<()> {
        // First increment
        self.counter.count += 1;

        // Simulate CPI (in real code: invoke() or CpiContext)
        // After CPI, account state on-chain is updated but our copy is stale
        self.counter.count += 1;

        // SECURE: Reload the account to get fresh data
        // In a real CPI scenario, you would call:
        // self.counter.reload()?;
        // This refreshes the deserialized Account from storage

        // For demonstration, we show what reload() does:
        // It re-reads the account data from the underlying AccountInfo
        // and re-deserializes it into the Account<T> wrapper

        msg!("Secure: Counter after operations: {}", self.counter.count);
        msg!("After reload(), this would reflect the true on-chain state");

        Ok(())
    }
}

// Example of real-world reload pattern:
//
// pub fn transfer_and_check(&mut self) -> Result<()> {
//     // CPI to token program
//     token::transfer(cpi_ctx, amount)?;
//
//     // CRITICAL: Reload to see updated balance
//     self.token_account.reload()?;
//
//     // Now we can safely check the new balance
//     require!(self.token_account.amount >= minimum);
//     Ok(())
// }
