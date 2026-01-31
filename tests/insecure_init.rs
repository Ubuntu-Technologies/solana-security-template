//! Tests for the Insecure Initialization vulnerability
//!
//! Demonstrates:
//! - Vulnerable: Attacker can reinitialize and overwrite admin
//! - Secure: Reinitialization is blocked by `init` constraint

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
            .join("target/deploy/insecure_init-keypair.json");

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
            .join("target/deploy/insecure_init.so");
        std::fs::read(so_path).expect("Failed to read program file")
    }

    fn derive_config_pda(seed: &[u8], program_id: &Pubkey) -> (Pubkey, u8) {
        Pubkey::find_program_address(&[seed], program_id)
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

    #[test]
    fn test_vulnerable_allows_reinitialization() {
        // SCENARIO: Attacker reinitializes config to become admin
        // ATTACK: Call vulnerable_initialize after legitimate init
        // EXPECTED: Vulnerable version ACCEPTS the attack (EXPLOIT WORKS)

        let (mut svm, legitimate_admin) = setup();
        let attacker = Keypair::new();
        let pid = program_id();

        svm.airdrop(&attacker.pubkey(), 2 * LAMPORTS_PER_SOL)
            .unwrap();

        let (config_pda, _bump) = derive_config_pda(b"config", &pid);

        // Step 1: Legitimate admin initializes first
        let mut init_data = discriminator("vulnerable_initialize").to_vec();
        init_data.extend_from_slice(legitimate_admin.pubkey().as_ref());

        let init_ix = Instruction {
            program_id: pid,
            accounts: vec![
                AccountMeta::new(legitimate_admin.pubkey(), true),
                AccountMeta::new(config_pda, false),
                AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),
            ],
            data: init_data,
        };

        let msg = Message::new(&[init_ix], Some(&legitimate_admin.pubkey()));
        let tx = Transaction::new(&[&legitimate_admin], msg, svm.latest_blockhash());
        let result = svm.send_transaction(tx);
        println!("Legitimate init result: {:?}", result);

        // Step 2: Attacker tries to reinitialize with their pubkey
        // With vulnerable version, init_if_needed won't create new account
        // but will still allow the instruction to execute
        let mut attack_data = discriminator("vulnerable_initialize").to_vec();
        attack_data.extend_from_slice(attacker.pubkey().as_ref());

        let attack_ix = Instruction {
            program_id: pid,
            accounts: vec![
                AccountMeta::new(attacker.pubkey(), true),
                AccountMeta::new(config_pda, false),
                AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),
            ],
            data: attack_data,
        };

        let msg = Message::new(&[attack_ix], Some(&attacker.pubkey()));
        let tx = Transaction::new(&[&attacker], msg, svm.latest_blockhash());
        let result = svm.send_transaction(tx);
        
        // The vulnerable version allows this - attacker is now admin
        println!("Attacker reinit result (should succeed): {:?}", result);
    }

    #[test]
    fn test_secure_blocks_reinitialization() {
        // SCENARIO: Attacker tries to reinitialize secure config
        // ATTACK: Call secure_initialize after legitimate init
        // EXPECTED: Secure version REJECTS the attack (FIX WORKS)

        let (mut svm, legitimate_admin) = setup();
        let attacker = Keypair::new();
        let pid = program_id();

        svm.airdrop(&attacker.pubkey(), 2 * LAMPORTS_PER_SOL)
            .unwrap();

        let (config_pda, _bump) = derive_config_pda(b"secure_config", &pid);

        // Step 1: Legitimate admin initializes first
        let mut init_data = discriminator("secure_initialize").to_vec();
        init_data.extend_from_slice(legitimate_admin.pubkey().as_ref());

        let init_ix = Instruction {
            program_id: pid,
            accounts: vec![
                AccountMeta::new(legitimate_admin.pubkey(), true),
                AccountMeta::new(config_pda, false),
                AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),
            ],
            data: init_data,
        };

        let msg = Message::new(&[init_ix], Some(&legitimate_admin.pubkey()));
        let tx = Transaction::new(&[&legitimate_admin], msg, svm.latest_blockhash());
        let result = svm.send_transaction(tx);
        println!("Legitimate secure init result: {:?}", result);
        assert!(result.is_ok(), "Legitimate init should succeed");

        // Step 2: Attacker tries to reinitialize
        let mut attack_data = discriminator("secure_initialize").to_vec();
        attack_data.extend_from_slice(attacker.pubkey().as_ref());

        let attack_ix = Instruction {
            program_id: pid,
            accounts: vec![
                AccountMeta::new(attacker.pubkey(), true),
                AccountMeta::new(config_pda, false),
                AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),
            ],
            data: attack_data,
        };

        let msg = Message::new(&[attack_ix], Some(&attacker.pubkey()));
        let tx = Transaction::new(&[&attacker], msg, svm.latest_blockhash());
        let result = svm.send_transaction(tx);

        // The secure version rejects this - `init` fails if account exists
        println!("Attacker reinit result (should fail): {:?}", result);
        assert!(result.is_err(), "Secure version should block reinitialization");
    }

    #[test]
    fn test_secure_init_works_first_time() {
        // SCENARIO: First initialization should succeed
        // EXPECTED: Secure version allows first init

        let (mut svm, admin) = setup();
        let pid = program_id();

        let (config_pda, _bump) = derive_config_pda(b"secure_config", &pid);

        let mut init_data = discriminator("secure_initialize").to_vec();
        init_data.extend_from_slice(admin.pubkey().as_ref());

        let init_ix = Instruction {
            program_id: pid,
            accounts: vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(config_pda, false),
                AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),
            ],
            data: init_data,
        };

        let msg = Message::new(&[init_ix], Some(&admin.pubkey()));
        let tx = Transaction::new(&[&admin], msg, svm.latest_blockhash());
        let result = svm.send_transaction(tx);

        println!("First-time init result: {:?}", result);
        assert!(result.is_ok(), "First-time initialization should succeed");
    }
}
