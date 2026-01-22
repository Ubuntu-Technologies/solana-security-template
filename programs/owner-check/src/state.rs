//! State definitions for owner-check program
//!
//! Using bytemuck for type-safe zero-copy deserialization.
//! This is safer than raw pointer manipulation.

use bytemuck::{Pod, Zeroable};

/// Config account storing an admin pubkey
/// Layout: [admin: Pubkey(32 bytes)]
#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct Config {
    pub admin: [u8; 32],
}

impl Config {
    pub const SIZE: usize = 32;
}
