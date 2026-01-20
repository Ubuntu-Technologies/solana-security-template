use anchor_lang::prelude::*;

use crate::state::Pool;

// ---------------------------------------------------------------------------
// Initialize Pool
// ---------------------------------------------------------------------------

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        init,
        payer = authority,
        space = 8 + Pool::INIT_SPACE,
        seeds = [b"pool", authority.key().as_ref()],
        bump
    )]
    pub pool: Account<'info, Pool>,

    pub system_program: Program<'info, System>,
}

impl<'info> Initialize<'info> {
    pub fn initialize(
        &mut self,
        bumps: &InitializeBumps,
        initial_x: u64,
        initial_y: u64,
        fee_bps: u16,
    ) -> Result<()> {
        self.pool.authority = self.authority.key();
        self.pool.reserve_x = initial_x;
        self.pool.reserve_y = initial_y;
        self.pool.fee_bps = fee_bps;
        self.pool.bump = bumps.pool;
        Ok(())
    }
}
