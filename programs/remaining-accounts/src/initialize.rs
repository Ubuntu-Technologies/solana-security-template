//! Initialize instruction for remaining-accounts program
//!
//! Shared initialization - not part of the vulnerability demonstration.

use anchor_lang::prelude::*;

use crate::state::BatchConfig;

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        init,
        payer = authority,
        space = 8 + 32 + 1,
        seeds = [b"config"],
        bump
    )]
    pub config: Account<'info, BatchConfig>,

    pub system_program: Program<'info, System>,
}

impl<'info> Initialize<'info> {
    pub fn initialize(&mut self, bumps: &InitializeBumps) -> Result<()> {
        self.config.authority = self.authority.key();
        self.config.bump = bumps.config;
        Ok(())
    }
}
