#![allow(unexpected_cfgs)]

use anchor_lang::prelude::*;

pub mod error;
pub mod initialize;
pub mod insecure;
pub mod secure;
pub mod state;

use initialize::*;
use insecure::*;
use secure::*;

declare_id!("Ar1thM3t1c111111111111111111111111111111111");

#[program]
pub mod arithmetic_overflow {
    use super::*;

    /// Initialize a new liquidity pool.
    pub fn initialize(
        ctx: Context<Initialize>,
        initial_x: u64,
        initial_y: u64,
        fee_bps: u16,
    ) -> Result<()> {
        ctx.accounts
            .initialize(&ctx.bumps, initial_x, initial_y, fee_bps)
    }

    /// INSECURE: Swap X for Y with vulnerable arithmetic.
    /// Demonstrates overflow and precision loss.
    pub fn insecure_swap(ctx: Context<InsecureSwap>, amount_in: u64, min_out: u64) -> Result<u64> {
        ctx.accounts.swap_x_for_y(amount_in, min_out)
    }

    /// SECURE: Swap X for Y with checked arithmetic.
    /// Uses u128 intermediates and slippage protection.
    pub fn secure_swap(ctx: Context<SecureSwap>, amount_in: u64, min_out: u64) -> Result<u64> {
        ctx.accounts.swap_x_for_y(amount_in, min_out)
    }
}
