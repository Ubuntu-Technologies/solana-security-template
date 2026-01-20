//! Deposit - VULNERABLE: No ownership validation on token accounts

use crate::state::Config;
use anchor_lang::prelude::*;
use anchor_spl::{
    associated_token::AssociatedToken,
    token::{mint_to, transfer, Mint, MintTo, Token, TokenAccount, Transfer},
};

#[derive(Accounts)]
pub struct Deposit<'info> {
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
        seeds = [b"config"],
        bump = config.config_bump,
    )]
    pub config: Account<'info, Config>,

    #[account(mut)]
    pub vault_x: Account<'info, TokenAccount>,

    #[account(mut)]
    pub vault_y: Account<'info, TokenAccount>,

    // VULN: No constraint checking these belong to user!
    // Attacker can pass victim's token accounts
    #[account(mut)]
    pub user_x: Account<'info, TokenAccount>,

    #[account(mut)]
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
        // VULN: Unchecked division
        let ratio = ctx.accounts.vault_x.amount / ctx.accounts.vault_y.amount;
        (max_x, max_x / ratio)
    };

    // VULN: Transfers from user_x/user_y without verifying ownership
    // If attacker passes victim's accounts, this CPI will fail
    // But shows the pattern of missing validation
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

    let seeds = &[b"config".as_ref(), &[ctx.accounts.config.config_bump]];
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
}
