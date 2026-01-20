use anchor_lang::prelude::*;

// ---------------------------------------------------------------------------
// Pool State
// ---------------------------------------------------------------------------
// Simple AMM pool with two token reserves.
// ---------------------------------------------------------------------------

#[account]
#[derive(InitSpace)]
pub struct Pool {
    pub authority: Pubkey,
    pub reserve_x: u64,
    pub reserve_y: u64,
    pub fee_bps: u16, // Fee in basis points (100 = 1%)
    pub bump: u8,
}
