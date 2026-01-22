use anchor_lang::prelude::*;

use crate::state::AuthConfig;

// ---------------------------------------------------------------------------
// VULNERABILITY: Insecure Authority Transfer
// ---------------------------------------------------------------------------
// Single-step transfer with no confirmation. If attacker exploits any bug
// to call this function, they immediately become admin. No recovery possible.
// Also vulnerable to typos - wrong address = lost forever.
// ---------------------------------------------------------------------------

#[derive(Accounts)]
pub struct VulnerableTransfer<'info> {
    pub authority: Signer<'info>,

    #[account(
        mut,
        seeds = [b"config"],
        bump = config.bump,
        has_one = authority
    )]
    pub config: Account<'info, AuthConfig>,
}

impl<'info> VulnerableTransfer<'info> {
    /// Transfer authority in one step.
    /// DANGER: No confirmation, no recovery, irreversible!
    pub fn transfer(&mut self, new_authority: Pubkey) -> Result<()> {
        // VULNERABLE: Immediate transfer - no verification that new_authority
        // is a valid address or that recipient can accept

        // No check for zero/invalid address
        // No two-step confirmation
        // No timelock
        // No multi-sig requirement

        self.config.authority = new_authority;

        msg!(
            "VULNERABLE: Authority transferred to {} immediately",
            new_authority
        );
        msg!("If this was a mistake or attack, there's NO WAY TO RECOVER!");

        Ok(())
    }
}
