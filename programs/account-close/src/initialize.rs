//! Initialize instruction for account-close program
//!
//! This is a shared initialization function used by both
//! vulnerable and secure versions. Not part of the vulnerability.

use crate::state::UserAccount;
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,

    #[account(
        init,
        payer = owner,
        space = 8 + UserAccount::INIT_SPACE,
        seeds = [b"user", owner.key().as_ref()],
        bump
    )]
    pub user_account: Account<'info, UserAccount>,

    pub system_program: Program<'info, System>,
}

impl<'info> Initialize<'info> {
    pub fn initialize(&mut self, bumps: &InitializeBumps) -> Result<()> {
        self.user_account.owner = self.owner.key();
        self.user_account.balance = 100; // Initial balance
        self.user_account.is_initialized = true;
        self.user_account.bump = bumps.user_account;
        Ok(())
    }
}

/// UseData instruction - used to demonstrate revival exploit
#[derive(Accounts)]
pub struct UseData<'info> {
    pub owner: Signer<'info>,

    #[account(
        seeds = [b"user", owner.key().as_ref()],
        bump = user_account.bump,
    )]
    pub user_account: Account<'info, UserAccount>,
}
