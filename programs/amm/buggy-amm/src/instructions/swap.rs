//! Swap - VULNERABLE: Arithmetic overflow + no slippage check

use crate::state::Config;
use anchor_lang::prelude::*;
use anchor_spl::token::{transfer, Mint, Token, TokenAccount, Transfer};

#[derive(Accounts)]
pub struct Swap<'info> {
    #[account(mut)]
    pub user: Signer<'info>,

    #[account(mut)]
    pub user_source: Account<'info, TokenAccount>,

    #[account(mut)]
    pub user_destination: Account<'info, TokenAccount>,

    pub source_mint: Account<'info, Mint>,
    pub destination_mint: Account<'info, Mint>,

    #[account(mut)]
    pub vault_source: Account<'info, TokenAccount>,

    #[account(mut)]
    pub vault_destination: Account<'info, TokenAccount>,

    #[account(
        seeds = [b"config"],
        bump = config.config_bump,
    )]
    pub config: Account<'info, Config>,

    pub token_program: Program<'info, Token>,
}

pub fn handler(ctx: Context<Swap>, amount_in: u64) -> Result<()> {
    let source_reserve = ctx.accounts.vault_source.amount;
    let dest_reserve = ctx.accounts.vault_destination.amount;

    // VULN: Unchecked multiplication - can overflow on large values
    let fee_adjusted = amount_in * (10000 - ctx.accounts.config.fee as u64) / 10000;

    // VULN: Unchecked math throughout - k = x * y can overflow
    let k = source_reserve * dest_reserve;
    let new_source = source_reserve + fee_adjusted;
    let new_dest = k / new_source;
    let amount_out = dest_reserve - new_dest;

    // VULN: No slippage check - min_out parameter ignored in lib.rs
    // Attacker can sandwich this transaction

    // Transfer in
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

    // Transfer out
    let seeds = &[b"config".as_ref(), &[ctx.accounts.config.config_bump]];
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
