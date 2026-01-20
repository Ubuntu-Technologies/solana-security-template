use anchor_lang::prelude::*;

use crate::error::PoolError;
use crate::state::Pool;

// ---------------------------------------------------------------------------
// SECURE: Checked Arithmetic with u128 Intermediates
// ---------------------------------------------------------------------------
// FIX: Use checked_* methods and u128 for intermediate calculations.
// This prevents overflow and maintains precision.
// ---------------------------------------------------------------------------

#[derive(Accounts)]
pub struct SecureSwap<'info> {
    #[account(mut)]
    pub user: Signer<'info>,

    #[account(
        mut,
        seeds = [b"pool", pool.authority.as_ref()],
        bump = pool.bump,
    )]
    pub pool: Account<'info, Pool>,
}

impl<'info> SecureSwap<'info> {
    /// Swap X for Y using safe arithmetic.
    pub fn swap_x_for_y(&mut self, amount_in: u64, min_out: u64) -> Result<u64> {
        require!(amount_in > 0, PoolError::InvalidAmount);

        let reserve_x = self.pool.reserve_x;
        let reserve_y = self.pool.reserve_y;

        // SECURE: Use u128 for intermediate calculations to prevent overflow
        let amount_in_u128 = amount_in as u128;
        let reserve_x_u128 = reserve_x as u128;
        let reserve_y_u128 = reserve_y as u128;

        // SECURE: checked_mul returns None on overflow
        let numerator = amount_in_u128
            .checked_mul(reserve_y_u128)
            .ok_or(PoolError::MathOverflow)?;

        let denominator = reserve_x_u128
            .checked_add(amount_in_u128)
            .ok_or(PoolError::MathOverflow)?;

        // SECURE: checked_div handles division
        let amount_out_u128 = numerator
            .checked_div(denominator)
            .ok_or(PoolError::MathOverflow)?;

        // SECURE: Ensure result fits in u64
        let amount_out = u64::try_from(amount_out_u128).map_err(|_| PoolError::MathOverflow)?;

        // SECURE: Slippage protection
        require!(amount_out >= min_out, PoolError::SlippageExceeded);
        require!(amount_out <= reserve_y, PoolError::InsufficientReserves);

        // Update reserves with checked math
        self.pool.reserve_x = reserve_x
            .checked_add(amount_in)
            .ok_or(PoolError::MathOverflow)?;
        self.pool.reserve_y = reserve_y
            .checked_sub(amount_out)
            .ok_or(PoolError::MathOverflow)?;

        Ok(amount_out)
    }
}
