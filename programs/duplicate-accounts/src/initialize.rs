//! Initialize instruction for duplicate-accounts program
//!
//! Shared initialization - not part of the vulnerability demonstration.

use anchor_lang::prelude::*;

use crate::state::UserBalance;

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub user: Signer<'info>,

    #[account(
        init,
        payer = user,
        space = 8 + 32 + 8 + 1,
        seeds = [b"balance", user.key().as_ref()],
        bump
    )]
    pub user_account: Account<'info, UserBalance>,

    pub system_program: Program<'info, System>,
}

impl<'info> Initialize<'info> {
    pub fn initialize(&mut self, bumps: &InitializeBumps, initial_balance: u64) -> Result<()> {
        self.user_account.owner = self.user.key();
        self.user_account.balance = initial_balance;
        self.user_account.bump = bumps.user_account;
        Ok(())
    }
}
