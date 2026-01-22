//! Initialize instruction for authority-transfer program
//!
//! Shared initialization - not part of the vulnerability demonstration.

use anchor_lang::prelude::*;

use crate::state::AuthConfig;

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        init,
        payer = authority,
        space = 8 + 32 + 33 + 1, // discriminator + authority + Option<Pubkey> + bump
        seeds = [b"config"],
        bump
    )]
    pub config: Account<'info, AuthConfig>,

    pub system_program: Program<'info, System>,
}

impl<'info> Initialize<'info> {
    pub fn initialize(&mut self, bumps: &InitializeBumps) -> Result<()> {
        self.config.authority = self.authority.key();
        self.config.pending_authority = None;
        self.config.bump = bumps.config;
        Ok(())
    }
}
