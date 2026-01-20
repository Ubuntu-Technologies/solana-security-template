//! Deposit - FIX: Proper Signer constraint

use crate::state::Config;
use anchor_lang::prelude::*;
use anchor_spl::{
    associated_token::AssociatedToken,
    token::{mint_to, transfer, Mint, MintTo, Token, TokenAccount, Transfer},
};

#[derive(Accounts)]
pub struct Deposit<'info> {
    // FIX: Signer<> ensures user authorized this transaction
    #[account(mut)]
    pub user: Signer<'info>,

    pub mint_x: Account<'info, Mint>,
    pub mint_y: Account<'info, Mint>,

    #[account(
        mut,
        seeds = [b"lp", config.key().as_ref()],
        bump = config.lp_bump
    )]
    pub mint_lp: Account<'info, Mint>,

    #[account(
        has_one = mint_x,
        has_one = mint_y,
        seeds = [b"config", config.seed.to_le_bytes().as_ref()],
        bump = config.config_bump,
    )]
    pub config: Account<'info, Config>,

    #[account(
        mut,
        associated_token::mint = mint_x,
        associated_token::authority = config
    )]
    pub vault_x: Account<'info, TokenAccount>,

    #[account(
        mut,
        associated_token::mint = mint_y,
        associated_token::authority = config
    )]
    pub vault_y: Account<'info, TokenAccount>,

    // FIX: Verify token accounts belong to user
    #[account(
        mut,
        constraint = user_x.owner == user.key(),
        constraint = user_x.mint == mint_x.key()
    )]
    pub user_x: Account<'info, TokenAccount>,

    #[account(
        mut,
        constraint = user_y.owner == user.key(),
        constraint = user_y.mint == mint_y.key()
    )]
    pub user_y: Account<'info, TokenAccount>,

    #[account(
        init_if_needed,
        payer = user,
        associated_token::mint = mint_lp,
        associated_token::authority = user,
    )]
    pub user_lp: Account<'info, TokenAccount>,

    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

pub fn handler(ctx: Context<Deposit>, amount: u64, max_x: u64, max_y: u64) -> Result<()> {
    require!(!ctx.accounts.config.locked, ErrorCode::PoolLocked);
    require!(amount > 0, ErrorCode::ZeroAmount);

    let (x, y) = if ctx.accounts.mint_lp.supply == 0 {
        (max_x, max_y)
    } else {
        // FIX: Checked math prevents overflow
        let ratio = ctx
            .accounts
            .vault_x
            .amount
            .checked_div(ctx.accounts.vault_y.amount)
            .ok_or(ErrorCode::MathError)?;
        let y_needed = max_x.checked_div(ratio).ok_or(ErrorCode::MathError)?;
        (max_x, y_needed.min(max_y))
    };

    require!(x <= max_x && y <= max_y, ErrorCode::SlippageExceeded);

    // Transfer with verified signer
    transfer(
        CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.user_x.to_account_info(),
                to: ctx.accounts.vault_x.to_account_info(),
                authority: ctx.accounts.user.to_account_info(),
            },
        ),
        x,
    )?;

    transfer(
        CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.user_y.to_account_info(),
                to: ctx.accounts.vault_y.to_account_info(),
                authority: ctx.accounts.user.to_account_info(),
            },
        ),
        y,
    )?;

    let seeds = &[
        b"config".as_ref(),
        &ctx.accounts.config.seed.to_le_bytes(),
        &[ctx.accounts.config.config_bump],
    ];
    let signer = &[&seeds[..]];

    mint_to(
        CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            MintTo {
                mint: ctx.accounts.mint_lp.to_account_info(),
                to: ctx.accounts.user_lp.to_account_info(),
                authority: ctx.accounts.config.to_account_info(),
            },
            signer,
        ),
        amount,
    )
}

#[error_code]
pub enum ErrorCode {
    #[msg("Pool is locked")]
    PoolLocked,
    #[msg("Amount must be greater than zero")]
    ZeroAmount,
    #[msg("Math error")]
    MathError,
    #[msg("Slippage exceeded")]
    SlippageExceeded,
}
