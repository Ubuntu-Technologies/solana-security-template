//! Tests for the Authority Transfer vulnerability
//!
//! Demonstrates:
//! - Vulnerable: Single-step immediate transfer with no confirmation
//! - Secure: Two-step propose/accept pattern requires new authority to sign

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use litesvm::LiteSVM;
    use solana_account::Account;
    use solana_instruction::{AccountMeta, Instruction};
    use solana_keypair::Keypair;
    use solana_message::Message;
    use solana_native_token::LAMPORTS_PER_SOL;
    use solana_pubkey::Pubkey;
    use solana_signer::Signer;
    use solana_transaction::Transaction;

    fn program_id() -> Pubkey {
        let keypair_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("target/deploy/authority_transfer-keypair.json");

        let keypair_bytes: Vec<u8> = serde_json::from_str(
            &std::fs::read_to_string(&keypair_path).expect("Failed to read keypair"),
        )
        .expect("Failed to parse keypair");

        Keypair::from_bytes(&keypair_bytes).unwrap().pubkey()
    }

    fn read_program() -> Vec<u8> {
        let so_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("target/deploy/authority_transfer.so");
        std::fs::read(so_path).expect("Failed to read program file")
    }

    fn derive_config_pda(program_id: &Pubkey) -> (Pubkey, u8) {
        Pubkey::find_program_address(&[b"config"], program_id)
    }

    /// Anchor-compatible discriminator
    fn discriminator(name: &str) -> [u8; 8] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(format!("global:{}", name));
        let result = hasher.finalize();
        let mut disc = [0u8; 8];
        disc.copy_from_slice(&result[..8]);
        disc
    }

    fn setup() -> (LiteSVM, Keypair) {
        let mut svm = LiteSVM::new();
        let payer = Keypair::new();
        svm.airdrop(&payer.pubkey(), 10 * LAMPORTS_PER_SOL)
            .expect("Airdrop failed");
        svm.add_program(program_id(), &read_program());
        (svm, payer)
    }

    fn setup_initialized_config(svm: &mut LiteSVM, authority: &Keypair) -> Pubkey {
        let pid = program_id();
        let (config_pda, bump) = derive_config_pda(&pid);

        // AuthConfig: authority (32) + pending_authority Option (1 + 32) + bump (1)
        // With Anchor discriminator (8)
        let mut config_data = vec![0u8; 8 + 32 + 1 + 32 + 1];
        // Set authority
        config_data[8..40].copy_from_slice(authority.pubkey().as_ref());
        // No pending authority (None = 0)
        config_data[40] = 0;
        // Bump
        config_data[73] = bump;

        svm.set_account(
            config_pda,
            Account {
                lamports: LAMPORTS_PER_SOL,
                data: config_data,
                owner: pid,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        config_pda
    }

    #[test]
    fn test_vulnerable_immediate_transfer() {
        // SCENARIO: Current authority can transfer to any address
        // ATTACK: If attacker gains access to call vulnerable_transfer, instant takeover
        // EXPECTED: Vulnerable version ACCEPTS immediate transfer (RISKY BEHAVIOR)

        let (mut svm, original_authority) = setup();
        let new_authority = Keypair::new();
        let pid = program_id();

        let config_pda = setup_initialized_config(&mut svm, &original_authority);

        // Vulnerable transfer - immediate, no confirmation needed
        let mut data = discriminator("vulnerable_transfer").to_vec();
        data.extend_from_slice(new_authority.pubkey().as_ref());

        let ix = Instruction {
            program_id: pid,
            accounts: vec![
                AccountMeta::new_readonly(original_authority.pubkey(), true),
                AccountMeta::new(config_pda, false),
            ],
            data,
        };

        let msg = Message::new(&[ix], Some(&original_authority.pubkey()));
        let tx = Transaction::new(&[&original_authority], msg, svm.latest_blockhash());
        let result = svm.send_transaction(tx);

        // This demonstrates the risky behavior - immediate transfer
        println!("Vulnerable transfer result: {:?}", result);
    }

    #[test]
    fn test_secure_requires_two_steps() {
        // SCENARIO: Secure two-step authority transfer
        // ATTACK: Try to accept without being the pending authority
        // EXPECTED: Secure version REJECTS unauthorized accept (FIX WORKS)

        let (mut svm, original_authority) = setup();
        let new_authority = Keypair::new();
        let unauthorized = Keypair::new();
        let pid = program_id();

        svm.airdrop(&new_authority.pubkey(), LAMPORTS_PER_SOL).unwrap();
        svm.airdrop(&unauthorized.pubkey(), LAMPORTS_PER_SOL).unwrap();

        let config_pda = setup_initialized_config(&mut svm, &original_authority);

        // Step 1: Original authority proposes new authority
        let mut propose_data = discriminator("propose_authority").to_vec();
        propose_data.extend_from_slice(new_authority.pubkey().as_ref());

        let propose_ix = Instruction {
            program_id: pid,
            accounts: vec![
                AccountMeta::new_readonly(original_authority.pubkey(), true),
                AccountMeta::new(config_pda, false),
            ],
            data: propose_data,
        };

        let msg = Message::new(&[propose_ix], Some(&original_authority.pubkey()));
        let tx = Transaction::new(&[&original_authority], msg, svm.latest_blockhash());
        let result = svm.send_transaction(tx);
        println!("Propose authority result: {:?}", result);

        // Step 2a: Unauthorized user tries to accept - should fail
        let accept_data = discriminator("accept_authority").to_vec();

        let unauthorized_ix = Instruction {
            program_id: pid,
            accounts: vec![
                AccountMeta::new_readonly(unauthorized.pubkey(), true),
                AccountMeta::new(config_pda, false),
            ],
            data: accept_data.clone(),
        };

        let msg = Message::new(&[unauthorized_ix], Some(&unauthorized.pubkey()));
        let tx = Transaction::new(&[&unauthorized], msg, svm.latest_blockhash());
        let result = svm.send_transaction(tx);
        
        println!("Unauthorized accept result (should fail): {:?}", result);
        assert!(result.is_err(), "Unauthorized user should not be able to accept");
    }

    #[test]
    fn test_secure_accept_works_for_pending() {
        // SCENARIO: Full two-step transfer flow
        // EXPECTED: New authority can accept after proposal

        let (mut svm, original_authority) = setup();
        let new_authority = Keypair::new();
        let pid = program_id();

        svm.airdrop(&new_authority.pubkey(), LAMPORTS_PER_SOL).unwrap();

        let (config_pda, bump) = derive_config_pda(&pid);

        // Set up config with pending authority already set
        let mut config_data = vec![0u8; 8 + 32 + 1 + 32 + 1];
        config_data[8..40].copy_from_slice(original_authority.pubkey().as_ref());
        // Set pending authority (Some = 1)
        config_data[40] = 1;
        config_data[41..73].copy_from_slice(new_authority.pubkey().as_ref());
        config_data[73] = bump;

        svm.set_account(
            config_pda,
            Account {
                lamports: LAMPORTS_PER_SOL,
                data: config_data,
                owner: pid,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        // New authority accepts
        let accept_data = discriminator("accept_authority").to_vec();

        let accept_ix = Instruction {
            program_id: pid,
            accounts: vec![
                AccountMeta::new_readonly(new_authority.pubkey(), true),
                AccountMeta::new(config_pda, false),
            ],
            data: accept_data,
        };

        let msg = Message::new(&[accept_ix], Some(&new_authority.pubkey()));
        let tx = Transaction::new(&[&new_authority], msg, svm.latest_blockhash());
        let result = svm.send_transaction(tx);

        println!("Legitimate accept result: {:?}", result);
    }
}
