//! Escrow state

use pinocchio::{account_info::AccountInfo, program_error::ProgramError};

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Escrow {
    /// The maker who created the escrow
    pub maker: [u8; 32],
    /// Token mint A (maker offers)
    pub mint_a: [u8; 32],
    /// Token mint B (maker wants)
    pub mint_b: [u8; 32],
    /// Amount maker wants to receive
    pub amount_to_receive: [u8; 8],
    /// Amount maker is giving
    pub amount_to_give: [u8; 8],
    /// PDA bump seed
    pub bump: u8,
    /// Whether the escrow is active
    pub is_active: u8,
}

impl Escrow {
    pub const LEN: usize = 32 + 32 + 32 + 8 + 8 + 1 + 1;

    #[allow(clippy::mut_from_ref)]
    pub fn from_account_info(account_info: &AccountInfo) -> Result<&mut Self, ProgramError> {
        let data = account_info.try_borrow_mut_data()?;

        if data.len() < Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }

        Ok(unsafe { &mut *(data.as_ptr() as *mut Self) })
    }

    pub fn maker(&self) -> pinocchio::pubkey::Pubkey {
        pinocchio::pubkey::Pubkey::from(self.maker)
    }

    pub fn set_maker(&mut self, maker: &pinocchio::pubkey::Pubkey) {
        self.maker.copy_from_slice(maker.as_ref());
    }

    pub fn amount_to_receive(&self) -> u64 {
        u64::from_le_bytes(self.amount_to_receive)
    }

    pub fn set_amount_to_receive(&mut self, amount: u64) {
        self.amount_to_receive = amount.to_le_bytes();
    }

    pub fn amount_to_give(&self) -> u64 {
        u64::from_le_bytes(self.amount_to_give)
    }

    pub fn set_amount_to_give(&mut self, amount: u64) {
        self.amount_to_give = amount.to_le_bytes();
    }
}
