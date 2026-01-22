use anchor_lang::prelude::*;

use crate::state::Config;

// ---------------------------------------------------------------------------
// VULNERABILITY: Insecure Initialization
// ---------------------------------------------------------------------------
// No check if account is already initialized. Uses init_if_needed incorrectly
// or doesn't check is_initialized flag, allowing attacker to reinitialize
// and overwrite the admin pubkey.
// ---------------------------------------------------------------------------

#[derive(Accounts)]
pub struct VulnerableInitialize<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(
        init_if_needed,  // VULNERABLE: allows re-initialization!
        payer = payer,
        space = Config::SIZE,
        seeds = [b"config"],
        bump
    )]
    pub config: Account<'info, Config>,

    pub system_program: Program<'info, System>,
}

impl<'info> VulnerableInitialize<'info> {
    /// Initialize or reinitialize the config.
    /// DANGER: No is_initialized check - anyone can overwrite admin!
    pub fn initialize(&mut self, admin: Pubkey) -> Result<()> {
        // VULNERABLE: We just overwrite, no check if already initialized
        self.config.admin = admin;
        self.config.is_initialized = true;
        // Note: if account exists, bump won't be set correctly either

        Ok(())
    }
}
