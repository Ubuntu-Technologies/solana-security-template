//! SECURE: Proper Owner Check
//!
//! THE FIX: Verify account.owner == program_id before reading data.

#![allow(unused)]

use pinocchio::{
    error::{ProgramError, ProgramResult},
    AccountView, Address,
};

/// SECURE: Read admin from config WITH owner verification
pub fn process_read_config(program_id: &Address, accounts: &[AccountView]) -> ProgramResult {
    let config_account = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;

    let caller = accounts.get(1).ok_or(ProgramError::NotEnoughAccountKeys)?;

    // ---------------------------------------------------------------------------
    // FIX: Verify the account is owned by our program!
    // SAFETY: owner() returns a reference to the owner pubkey
    // ---------------------------------------------------------------------------
    if unsafe { config_account.owner() } != program_id {
        return Err(ProgramError::IllegalOwner);
    }

    // Now we can safely read data
    let config_data = config_account.try_borrow()?;
    if config_data.len() < 32 {
        return Err(ProgramError::InvalidAccountData);
    }

    let stored_admin = &config_data[..32];

    if caller.address().as_ref() != stored_admin {
        return Err(ProgramError::InvalidAccountData);
    }

    // SECURE: Admin action with verified owner
    Ok(())
}
