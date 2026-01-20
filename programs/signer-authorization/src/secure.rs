use anchor_lang::prelude::*;

use crate::error::VaultError;
use crate::state::Vault;

// ---------------------------------------------------------------------------
// SECURE: Proper Signer Validation
// ---------------------------------------------------------------------------
// FIX: Use Signer<'info> type which enforces that the authority must sign
// the transaction. Combined with constraint check against stored authority.
// ---------------------------------------------------------------------------

#[derive(Accounts)]
pub struct SecureWithdraw<'info> {
    #[account(
        mut,
        seeds = [b"vault", authority.key().as_ref()],
        bump = vault.bump,
        // SECURE: Verify signer matches stored authority
        constraint = vault.authority == authority.key() @ VaultError::UnauthorizedAuthority
    )]
    pub vault: Account<'info, Vault>,

    /// SECURE: Signer type enforces that this account must sign the transaction.
    pub authority: Signer<'info>,

    #[account(mut)]
    /// CHECK: Destination for lamports
    pub destination: UncheckedAccount<'info>,
}

impl<'info> SecureWithdraw<'info> {
    /// Withdraw lamports from vault.
    /// Only the vault authority can call this.
    pub fn withdraw(&mut self, amount: u64) -> Result<()> {
        // Modern pattern: use Lamports trait for direct transfers
        // Safe because Signer constraint ensures authority signed
        self.vault.sub_lamports(amount)?;
        self.destination.add_lamports(amount)?;

        Ok(())
    }
}
