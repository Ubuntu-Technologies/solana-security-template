use anchor_lang::prelude::*;

use crate::state::BatchConfig;

// ---------------------------------------------------------------------------
// VULNERABILITY: Unvalidated Remaining Accounts
// ---------------------------------------------------------------------------
// ctx.remaining_accounts are NOT validated by Anchor. They bypass all
// constraints. If you iterate over them and perform operations, an attacker
// can pass malicious accounts.
// ---------------------------------------------------------------------------

#[derive(Accounts)]
pub struct VulnerableBatchReward<'info> {
    pub authority: Signer<'info>,

    #[account(
        seeds = [b"config"],
        bump = config.bump,
        has_one = authority
    )]
    pub config: Account<'info, BatchConfig>,
    // remaining_accounts will contain reward recipients
    // BUT THEY ARE NOT VALIDATED!
}

impl<'info> VulnerableBatchReward<'info> {
    /// Process rewards to all remaining accounts.
    /// DANGER: No validation on remaining_accounts!
    pub fn process_rewards(
        &self,
        remaining: &[AccountInfo<'info>],
        amounts: Vec<u64>,
    ) -> Result<()> {
        // VULNERABLE: No owner check, no type check, no eligibility check
        for (i, account) in remaining.iter().enumerate() {
            let amount = amounts.get(i).copied().unwrap_or(0);

            // Just blindly "reward" - attacker could pass ANY account
            msg!(
                "VULNERABLE: Rewarding {} with {} (no validation!)",
                account.key(),
                amount
            );

            // In reality, this might transfer tokens, update balances, etc.
            // Attacker passes their own accounts -> steals rewards
        }

        Ok(())
    }
}
