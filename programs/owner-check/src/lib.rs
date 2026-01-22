//! Owner Check - Pinocchio Program
//!
//! Demonstrates the "Missing Owner Check" vulnerability.
//!
//! Uses bytemuck for type-safe zero-copy deserialization,
//! which is safer than raw pointer manipulation.

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

use state::Config;

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
        0 => vulnerable::process_read_config(program_id, accounts),
        1 => secure::process_read_config(program_id, accounts),
        2 => initialize_config(program_id, accounts, instruction_data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// Initialize a config account using bytemuck for safe writes
fn initialize_config(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let config_account = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;

    // Must be owned by this program
    if unsafe { config_account.owner() } != program_id {
        return Err(ProgramError::IllegalOwner);
    }

    if data.len() < 33 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let admin_pubkey: [u8; 32] = data[1..33]
        .try_into()
        .map_err(|_| ProgramError::InvalidInstructionData)?;

    // Use bytemuck for safe writes
    unsafe {
        let config_data = config_account.borrow_unchecked();
        if config_data.len() < Config::SIZE {
            return Err(ProgramError::InvalidAccountData);
        }

        // Create a Config struct and write its bytes
        let mut config = Config {
            admin: admin_pubkey,
        };
        let config_bytes = bytes_of_mut(&mut config);

        core::ptr::copy_nonoverlapping(
            config_bytes.as_ptr(),
            config_data.as_ptr() as *mut u8,
            Config::SIZE,
        );
    }

    Ok(())
}
