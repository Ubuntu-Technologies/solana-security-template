//! Type Cosplay - Pinocchio Program
//!
//! Demonstrates the "Type Cosplay" or "Missing Discriminator" vulnerability.
//!
//! VULNERABILITY: When accounts don't have a discriminator (type identifier),
//! an attacker can pass an account of type A where type B is expected.
//! If both have the same serialized layout, the program reads garbage data.
//!
//! Uses bytemuck for type-safe zero-copy deserialization.

#![no_std]

use bytemuck::bytes_of_mut;
use pinocchio::{
    entrypoint,
    error::{ProgramError, ProgramResult},
    nostd_panic_handler, AccountView, Address,
};

mod secure;
mod state;
mod vulnerable;

use state::{Admin, User, ADMIN_DISCRIMINATOR, USER_DISCRIMINATOR};

entrypoint!(process_instruction);
nostd_panic_handler!();

/// Main entry point
pub fn process_instruction(
    program_id: &Address,
    accounts: &[AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    let instruction = instruction_data
        .first()
        .ok_or(ProgramError::InvalidInstructionData)?;

    match instruction {
        // 0 = Vulnerable: Read user without discriminator check
        0 => vulnerable::process_action(program_id, accounts),
        // 1 = Secure: Read user WITH discriminator verification
        1 => secure::process_action(program_id, accounts),
        // 2 = Initialize user account
        2 => init_user(program_id, accounts, instruction_data),
        // 3 = Initialize admin account
        3 => init_admin(program_id, accounts, instruction_data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// Initialize user account using bytemuck for safe writes
fn init_user(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let account = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;

    if unsafe { account.owner() } != program_id {
        return Err(ProgramError::IllegalOwner);
    }

    if data.len() < 33 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let pubkey: [u8; 32] = data[1..33]
        .try_into()
        .map_err(|_| ProgramError::InvalidInstructionData)?;

    // Create User struct with bytemuck
    let mut user = User {
        discriminator: USER_DISCRIMINATOR,
        _padding: [0u8; 7],
        balance: 0,
        pubkey,
    };

    unsafe {
        let acc_data = account.borrow_unchecked();
        if acc_data.len() < User::SIZE {
            return Err(ProgramError::InvalidAccountData);
        }

        let user_bytes = bytes_of_mut(&mut user);
        core::ptr::copy_nonoverlapping(
            user_bytes.as_ptr(),
            acc_data.as_ptr() as *mut u8,
            User::SIZE,
        );
    }

    Ok(())
}

/// Initialize admin account using bytemuck for safe writes
fn init_admin(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let account = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;

    if unsafe { account.owner() } != program_id {
        return Err(ProgramError::IllegalOwner);
    }

    if data.len() < 33 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let pubkey: [u8; 32] = data[1..33]
        .try_into()
        .map_err(|_| ProgramError::InvalidInstructionData)?;

    // Create Admin struct with bytemuck
    let mut admin = Admin {
        discriminator: ADMIN_DISCRIMINATOR,
        _padding: [0u8; 7],
        permissions: 0,
        pubkey,
    };

    unsafe {
        let acc_data = account.borrow_unchecked();
        if acc_data.len() < Admin::SIZE {
            return Err(ProgramError::InvalidAccountData);
        }

        let admin_bytes = bytes_of_mut(&mut admin);
        core::ptr::copy_nonoverlapping(
            admin_bytes.as_ptr(),
            acc_data.as_ptr() as *mut u8,
            Admin::SIZE,
        );
    }

    Ok(())
}
