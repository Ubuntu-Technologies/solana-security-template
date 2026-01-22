//! State definitions for account-type-mismatch program
//!
//! Using bytemuck for type-safe zero-copy deserialization.
//! This demonstrates the importance of discriminators.
//!
//! Note: Structs use [u8; 7] padding to ensure no implicit padding
//! and satisfy bytemuck's Pod requirements.

use bytemuck::{Pod, Zeroable};

/// Discriminator values to distinguish account types
pub const USER_DISCRIMINATOR: u8 = 1;
pub const ADMIN_DISCRIMINATOR: u8 = 2;

/// User account
/// Layout: [discriminator(1), _padding(7), balance(8), pubkey(32)] = 48 bytes
/// We put balance before pubkey to align u64 on 8-byte boundary
#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct User {
    pub discriminator: u8,
    pub _padding: [u8; 7],
    pub balance: u64,
    pub pubkey: [u8; 32],
}

impl User {
    pub const SIZE: usize = 48;
}

/// Admin account - intentionally same size as User for vulnerability demo
/// Layout: [discriminator(1), _padding(7), permissions(8), pubkey(32)] = 48 bytes
#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct Admin {
    pub discriminator: u8,
    pub _padding: [u8; 7],
    pub permissions: u64,
    pub pubkey: [u8; 32],
}

impl Admin {
    pub const SIZE: usize = 48;
}
