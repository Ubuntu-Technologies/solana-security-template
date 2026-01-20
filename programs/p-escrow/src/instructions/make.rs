//! Make instruction - Create an escrow offer

use pinocchio::{
    account_info::AccountInfo,
    instruction::{Seed, Signer},
    sysvars::{rent::Rent, Sysvar},
    ProgramResult,
};
use pinocchio_system::instructions::CreateAccount;

use crate::state::Escrow;

pub fn process_make(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [maker, mint_a, mint_b, escrow_account, maker_ata, vault, system_program, token_program, ..] =
        accounts
    else {
        return Err(pinocchio::program_error::ProgramError::NotEnoughAccountKeys);
    };

    // Parse instruction data
    if data.len() < 17 {
        return Err(pinocchio::program_error::ProgramError::InvalidInstructionData);
    }

    let bump = data[0];
    let amount_to_receive = unsafe { *(data.as_ptr().add(1) as *const u64) };
    let amount_to_give = unsafe { *(data.as_ptr().add(9) as *const u64) };

    // Create escrow PDA
    let bump_bytes = [bump];
    let seeds = [
        Seed::from(b"escrow"),
        Seed::from(maker.key()),
        Seed::from(&bump_bytes),
    ];
    let signer = Signer::from(&seeds);

    if escrow_account.owner() != &crate::ID {
        CreateAccount {
            from: maker,
            to: escrow_account,
            lamports: Rent::get()?.minimum_balance(Escrow::LEN),
            space: Escrow::LEN as u64,
            owner: &crate::ID,
        }
        .invoke_signed(&[signer])?;

        let escrow_state = Escrow::from_account_info(escrow_account)?;
        escrow_state.set_maker(maker.key());
        escrow_state.mint_a.copy_from_slice(mint_a.key().as_ref());
        escrow_state.mint_b.copy_from_slice(mint_b.key().as_ref());
        escrow_state.set_amount_to_receive(amount_to_receive);
        escrow_state.set_amount_to_give(amount_to_give);
        escrow_state.bump = bump;
        escrow_state.is_active = 1;
    }

    // Transfer tokens to vault
    pinocchio_token::instructions::Transfer {
        from: maker_ata,
        to: vault,
        authority: maker,
        amount: amount_to_give,
    }
    .invoke()?;

    Ok(())
}
