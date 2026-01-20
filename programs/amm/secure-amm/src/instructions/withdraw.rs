//! Withdraw - FIX: Proper vault ownership + slippage protection

use crate::state::Config;
use anchor_lang::prelude::*;
use anchor_spl::token::{burn, transfer, Burn, Mint, Token, TokenAccount, Transfer};

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub user: Signer<'info>,

    #[account(
        mut,
        constraint = user_x.owner == user.key(),
        constraint = user_x.mint == config.mint_x
    )]
    pub user_x: Account<'info, TokenAccount>,

    #[account(
        mut,
        constraint = user_y.owner == user.key(),
        constraint = user_y.mint == config.mint_y
    )]
    pub user_y: Account<'info, TokenAccount>,

    #[account(
        mut,
        constraint = user_lp.owner == user.key(),
        constraint = user_lp.mint == mint_lp.key()
    )]
    pub user_lp: Account<'info, TokenAccount>,

    #[account(address = config.mint_x)]
    pub mint_x: Account<'info, Mint>,

    #[account(address = config.mint_y)]
    pub mint_y: Account<'info, Mint>,

    #[account(
        mut,
        seeds = [b"lp", config.key().as_ref()],
        bump = config.lp_bump,
    )]
    pub mint_lp: Account<'info, Mint>,

    // FIX: Verify vaults belong to this config
    #[account(
        mut,
        associated_token::mint = mint_x,
        associated_token::authority = config,
    )]
    pub vault_x: Account<'info, TokenAccount>,

    #[account(
        mut,
        associated_token::mint = mint_y,
        associated_token::authority = config,
    )]
    pub vault_y: Account<'info, TokenAccount>,

    #[account(
        seeds = [b"config", config.seed.to_le_bytes().as_ref()],
        bump = config.config_bump,
    )]
    pub config: Account<'info, Config>,

    pub token_program: Program<'info, Token>,
}

pub fn handler(ctx: Context<Withdraw>, lp_amount: u64, min_x: u64, min_y: u64) -> Result<()> {
    require!(lp_amount > 0, ErrorCode::ZeroAmount);

    let lp_supply = ctx.accounts.mint_lp.supply as u128;
    require!(lp_supply > 0, ErrorCode::NoLiquidity);

    // FIX: Checked math for proportional calculation
    let x_amount = (ctx.accounts.vault_x.amount as u128)
        .checked_mul(lp_amount as u128)
        .ok_or(ErrorCode::MathOverflow)?
        .checked_div(lp_supply)
        .ok_or(ErrorCode::MathOverflow)? as u64;

    let y_amount = (ctx.accounts.vault_y.amount as u128)
        .checked_mul(lp_amount as u128)
        .ok_or(ErrorCode::MathOverflow)?
        .checked_div(lp_supply)
        .ok_or(ErrorCode::MathOverflow)? as u64;

    // FIX: Slippage protection
    require!(x_amount >= min_x, ErrorCode::SlippageExceeded);
    require!(y_amount >= min_y, ErrorCode::SlippageExceeded);

    // Burn LP tokens first
    burn(
        CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            Burn {
                mint: ctx.accounts.mint_lp.to_account_info(),
                from: ctx.accounts.user_lp.to_account_info(),
                authority: ctx.accounts.user.to_account_info(),
            },
        ),
        lp_amount,
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
                from: ctx.accounts.vault_x.to_account_info(),
                to: ctx.accounts.user_x.to_account_info(),
                authority: ctx.accounts.config.to_account_info(),
            },
            signer,
        ),
        x_amount,
    )?;

    transfer(
        CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.vault_y.to_account_info(),
                to: ctx.accounts.user_y.to_account_info(),
                authority: ctx.accounts.config.to_account_info(),
            },
            signer,
        ),
        y_amount,
    )
}

#[error_code]
pub enum ErrorCode {
    #[msg("Amount must be greater than zero")]
    ZeroAmount,
    #[msg("No liquidity in pool")]
    NoLiquidity,
    #[msg("Math overflow")]
    MathOverflow,
    #[msg("Slippage tolerance exceeded")]
    SlippageExceeded,
}
