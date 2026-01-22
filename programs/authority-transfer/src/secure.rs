use anchor_lang::prelude::*;

use crate::error::AuthError;
use crate::state::AuthConfig;

// ---------------------------------------------------------------------------
// SECURE: Two-Step Authority Transfer
// ---------------------------------------------------------------------------
// FIX: Require the new authority to accept the transfer. This proves:
// 1. The new address is valid and controlled by someone
// 2. The recipient is aware and consenting
// 3. Typos or attacks don't result in permanent lockout
// ---------------------------------------------------------------------------

#[derive(Accounts)]
pub struct ProposeAuthority<'info> {
    pub authority: Signer<'info>,

    #[account(
        mut,
        seeds = [b"config"],
        bump = config.bump,
        has_one = authority
    )]
    pub config: Account<'info, AuthConfig>,
}

impl<'info> ProposeAuthority<'info> {
    /// Step 1: Propose a new authority.
    /// SAFE: This doesn't actually transfer - just marks pending.
    pub fn propose(&mut self, new_authority: Pubkey) -> Result<()> {
        // SECURE: Check for zero address
        require!(new_authority != Pubkey::default(), AuthError::ZeroAddress);

        // Set pending, don't transfer yet
        self.config.pending_authority = Some(new_authority);

        msg!("Authority transfer proposed to: {}", new_authority);
        msg!("New authority must call accept_authority to complete transfer");

        Ok(())
    }
}

#[derive(Accounts)]
pub struct AcceptAuthority<'info> {
    /// The pending authority must sign to accept
    pub new_authority: Signer<'info>,

    #[account(
        mut,
        seeds = [b"config"],
        bump = config.bump,
    )]
    pub config: Account<'info, AuthConfig>,
}

impl<'info> AcceptAuthority<'info> {
    /// Step 2: Accept authority transfer.
    /// SAFE: Only the pending authority can complete the transfer.
    pub fn accept(&mut self) -> Result<()> {
        // SECURE: Verify there's a pending transfer
        let pending = self
            .config
            .pending_authority
            .ok_or(AuthError::NoPendingAuthority)?;

        // SECURE: Verify the signer is the pending authority
        require!(
            self.new_authority.key() == pending,
            AuthError::NotPendingAuthority
        );

        // Now safe to transfer
        self.config.authority = pending;
        self.config.pending_authority = None;

        msg!("Authority transfer accepted and completed");
        msg!("New authority: {}", self.config.authority);

        Ok(())
    }
}
