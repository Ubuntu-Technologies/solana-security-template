//! Withdraw - VULNERABLE: No owner check + account revival

use crate::state::Config;
use anchor_lang::prelude::*;
use anchor_spl::token::{burn, transfer, Burn, Mint, Token, TokenAccount, Transfer};

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub user: Signer<'info>,

    #[account(mut)]
    pub user_x: Account<'info, TokenAccount>,

    #[account(mut)]
    pub user_y: Account<'info, TokenAccount>,

    #[account(mut)]
    pub user_lp: Account<'info, TokenAccount>,

    pub mint_x: Account<'info, Mint>,
    pub mint_y: Account<'info, Mint>,

    #[account(mut)]
    pub mint_lp: Account<'info, Mint>,

    // VULN: No constraint checking vault ownership
    // Attacker can pass fake vaults
    #[account(mut)]
    pub vault_x: Account<'info, TokenAccount>,

    #[account(mut)]
    pub vault_y: Account<'info, TokenAccount>,

    // VULN: No close constraint - account can be revived
    #[account(
        mut,
        seeds = [b"config"],
        bump = config.config_bump,
    )]
    pub config: Account<'info, Config>,

    pub token_program: Program<'info, Token>,
}

pub fn handler(ctx: Context<Withdraw>, lp_amount: u64) -> Result<()> {
    let lp_supply = ctx.accounts.mint_lp.supply;

    // VULN: Unchecked division - no zero check on lp_supply
    let x_amount = ctx.accounts.vault_x.amount * lp_amount / lp_supply;
    let y_amount = ctx.accounts.vault_y.amount * lp_amount / lp_supply;

    // Burn LP tokens
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

    let seeds = &[b"config".as_ref(), &[ctx.accounts.config.config_bump]];
    let signer = &[&seeds[..]];

    // Transfer X
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

    // Transfer Y
    // VULN: No data zeroing if this fully drains - revival possible
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
