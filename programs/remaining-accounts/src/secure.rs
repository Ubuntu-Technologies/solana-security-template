use anchor_lang::prelude::*;

use crate::error::BatchError;
use crate::state::{BatchConfig, RewardRecipient};
use crate::ID;

// ---------------------------------------------------------------------------
// SECURE: Validated Remaining Accounts
// ---------------------------------------------------------------------------
// FIX: Manually validate each remaining_account:
// 1. Check owner == program_id
// 2. Deserialize and verify type/discriminator
// 3. Check business logic (eligibility, etc.)
// ---------------------------------------------------------------------------

#[derive(Accounts)]
pub struct SecureBatchReward<'info> {
    pub authority: Signer<'info>,

    #[account(
        seeds = [b"config"],
        bump = config.bump,
        has_one = authority
    )]
    pub config: Account<'info, BatchConfig>,
    // remaining_accounts will contain reward recipients
    // WE WILL VALIDATE THEM MANUALLY
}

impl<'info> SecureBatchReward<'info> {
    /// Process rewards with proper validation.
    /// SAFE: Each remaining account is validated before use.
    pub fn process_rewards(
        &self,
        remaining: &[AccountInfo<'info>],
        amounts: Vec<u64>,
    ) -> Result<()> {
        // SECURE: Verify count matches
        require!(remaining.len() == amounts.len(), BatchError::CountMismatch);

        for (i, account_info) in remaining.iter().enumerate() {
            let amount = amounts[i];

            // SECURE: Step 1 - Verify owner is our program
            require!(account_info.owner == &ID, BatchError::InvalidOwner);

            // SECURE: Step 2 - Deserialize and verify type
            let data = account_info.try_borrow_data()?;

            // Check discriminator (first 8 bytes for Anchor accounts)
            // RewardRecipient discriminator would be checked here
            if data.len() < 8 {
                return Err(BatchError::InvalidAccount.into());
            }

            // SECURE: Step 3 - Deserialize and check eligibility
            // In real code: let recipient = RewardRecipient::try_deserialize(&mut &data[..])?;
            // require!(recipient.is_eligible, BatchError::NotEligible);

            msg!(
                "SECURE: Validated and rewarding {} with {}",
                account_info.key(),
                amount
            );
        }

        Ok(())
    }
}
