//! SECURE: Proper Discriminator Verification
//!
//! THE FIX:
//! Always check the account's discriminator (first byte) before reading data.
//! This ensures you're reading the correct account type.

#![allow(unused)]

use crate::USER_DISCRIMINATOR;
use pinocchio::{
    error::{ProgramError, ProgramResult},
    AccountView, Address,
};

/// SECURE: Read user data WITH type verification
pub fn process_action(program_id: &Address, accounts: &[AccountView]) -> ProgramResult {
    let user_account = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;

    let caller = accounts.get(1).ok_or(ProgramError::NotEnoughAccountKeys)?;

    // Verify owner
    if unsafe { user_account.owner() } != program_id {
        return Err(ProgramError::IllegalOwner);
    }

    let data = user_account.try_borrow()?;
    if data.len() < 41 {
        return Err(ProgramError::InvalidAccountData);
    }

    // ---------------------------------------------------------------------------
    // FIX: Check discriminator FIRST!
    // This ensures we're reading a User account, not an Admin account
    // ---------------------------------------------------------------------------
    let discriminator = data[0];
    if discriminator != USER_DISCRIMINATOR {
        // Wrong account type - reject immediately
        return Err(ProgramError::InvalidAccountData);
    }

    // Now we can safely read user data
    let stored_user = &data[1..33];
    let balance = u64::from_le_bytes(
        data[33..41]
            .try_into()
            .map_err(|_| ProgramError::InvalidAccountData)?,
    );

    if caller.address().as_ref() != stored_user {
        return Err(ProgramError::InvalidAccountData);
    }

    // SECURE: We verified this is actually a User account
    // balance is definitely User.balance, not Admin.permissions

    Ok(())
}
