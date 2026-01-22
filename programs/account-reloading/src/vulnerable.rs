use anchor_lang::prelude::*;

use crate::state::Counter;

// ---------------------------------------------------------------------------
// VULNERABILITY: Account Reloading
// ---------------------------------------------------------------------------
// After a CPI that modifies an account, Anchor does NOT automatically refresh
// the deserialized account data. Any subsequent logic using the account
// will operate on stale data from before the CPI.
// ---------------------------------------------------------------------------

#[derive(Accounts)]
pub struct VulnerableDoubleIncrement<'info> {
    pub authority: Signer<'info>,

    #[account(
        mut,
        seeds = [b"counter", authority.key().as_ref()],
        bump = counter.bump,
        has_one = authority
    )]
    pub counter: Account<'info, Counter>,
}

impl<'info> VulnerableDoubleIncrement<'info> {
    /// Double increment the counter.
    /// DANGER: After first increment, counter.count is STALE!
    pub fn double_increment(&mut self) -> Result<()> {
        // First increment - directly modify
        self.counter.count += 1;
        let first_value = self.counter.count;

        // Simulate CPI that also increments (in real scenario, this would be invoke())
        // For demo, we just increment again
        self.counter.count += 1;

        // VULNERABLE: If this were a real CPI, counter.count would be stale
        // We'd think count is `first_value` but blockchain has `first_value + 1`
        // Any logic using self.counter.count here would be wrong!

        msg!(
            "Vulnerable: Counter after operations: {}",
            self.counter.count
        );
        msg!("WARNING: In real CPI scenario, this value would be STALE!");

        Ok(())
    }
}
