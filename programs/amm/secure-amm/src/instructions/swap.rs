//! Swap - FIX: Checked math + slippage protection

use crate::state::Config;
use anchor_lang::prelude::*;
use anchor_spl::token::{transfer, Mint, Token, TokenAccount, Transfer};

#[derive(Accounts)]
pub struct Swap<'info> {
    #[account(mut)]
    pub user: Signer<'info>,

    #[account(
        mut,
        constraint = user_source.owner == user.key()
    )]
    pub user_source: Account<'info, TokenAccount>,

    #[account(
        mut,
        constraint = user_destination.owner == user.key()
    )]
    pub user_destination: Account<'info, TokenAccount>,

    pub source_mint: Account<'info, Mint>,
    pub destination_mint: Account<'info, Mint>,

    // FIX: Verify vault authority matches config PDA
    #[account(
        mut,
        constraint = vault_source.owner == config.key()
    )]
    pub vault_source: Account<'info, TokenAccount>,

    #[account(
        mut,
        constraint = vault_destination.owner == config.key()
    )]
    pub vault_destination: Account<'info, TokenAccount>,

    #[account(
        seeds = [b"config", config.seed.to_le_bytes().as_ref()],
        bump = config.config_bump,
    )]
    pub config: Account<'info, Config>,

    pub token_program: Program<'info, Token>,
}

pub fn handler(ctx: Context<Swap>, amount_in: u64, min_out: u64) -> Result<()> {
    require!(amount_in > 0, ErrorCode::ZeroAmount);
    require!(min_out > 0, ErrorCode::ZeroAmount);
    require!(!ctx.accounts.config.locked, ErrorCode::PoolLocked);

    let source_reserve = ctx.accounts.vault_source.amount as u128;
    let dest_reserve = ctx.accounts.vault_destination.amount as u128;
    let fee = ctx.accounts.config.fee as u128;

    // FIX: All math uses checked operations
    let fee_adjusted = (amount_in as u128)
        .checked_mul(10000 - fee)
        .ok_or(ErrorCode::MathOverflow)?
        .checked_div(10000)
        .ok_or(ErrorCode::MathOverflow)?;

    // Constant product: k = x * y
    let k = source_reserve
        .checked_mul(dest_reserve)
        .ok_or(ErrorCode::MathOverflow)?;

    let new_source = source_reserve
        .checked_add(fee_adjusted)
        .ok_or(ErrorCode::MathOverflow)?;

    let new_dest = k.checked_div(new_source).ok_or(ErrorCode::MathOverflow)?;

    let amount_out = dest_reserve
        .checked_sub(new_dest)
        .ok_or(ErrorCode::MathOverflow)? as u64;

    // FIX: Slippage protection - revert if output too low
    require!(amount_out >= min_out, ErrorCode::SlippageExceeded);

    // Transfer tokens
    transfer(
        CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.user_source.to_account_info(),
                to: ctx.accounts.vault_source.to_account_info(),
                authority: ctx.accounts.user.to_account_info(),
            },
        ),
        amount_in,
    )?;

    let seeds = &[
        b"config".as_ref(),
        &ctx.accounts.config.seed.to_le_bytes(),
        &[ctx.accounts.config.config_bump],
    ];
    let signer = &[&seeds[..]];

    transfer(
        CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.vault_destination.to_account_info(),
                to: ctx.accounts.user_destination.to_account_info(),
                authority: ctx.accounts.config.to_account_info(),
            },
            signer,
        ),
        amount_out,
    )
}

#[error_code]
pub enum ErrorCode {
    #[msg("Amount must be greater than zero")]
    ZeroAmount,
    #[msg("Pool is locked")]
    PoolLocked,
    #[msg("Math overflow")]
    MathOverflow,
    #[msg("Slippage tolerance exceeded")]
    SlippageExceeded,
}
