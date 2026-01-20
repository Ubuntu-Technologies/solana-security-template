use anchor_lang::prelude::*;

use crate::state::Vault;

// ---------------------------------------------------------------------------
// Initialize Vault
// ---------------------------------------------------------------------------

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        init,
        payer = authority,
        space = 8 + Vault::INIT_SPACE,
        seeds = [b"vault", authority.key().as_ref()],
        bump
    )]
    pub vault: Account<'info, Vault>,

    pub system_program: Program<'info, System>,
}

impl<'info> Initialize<'info> {
    pub fn initialize(&mut self, bumps: &InitializeBumps) -> Result<()> {
        self.vault.authority = self.authority.key();
        self.vault.bump = bumps.vault;
        Ok(())
    }

    /// Deposit lamports into the vault.
    pub fn deposit(&mut self, amount: u64) -> Result<()> {
        // Modern pattern: use Lamports trait for transfers
        self.authority.sub_lamports(amount)?;
        self.vault.add_lamports(amount)?;
        Ok(())
    }
}
