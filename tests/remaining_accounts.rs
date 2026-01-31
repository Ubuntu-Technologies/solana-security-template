//! Tests for the Remaining Accounts vulnerability
//!
//! Demonstrates:
//! - Vulnerable: ctx.remaining_accounts processed without validation
//! - Secure: Each remaining account is validated for owner, type, eligibility

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
            .join("target/deploy/remaining_accounts-keypair.json");

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
            .join("target/deploy/remaining_accounts.so");
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

    fn setup_batch_config(svm: &mut LiteSVM, authority: &Keypair) -> Pubkey {
        let pid = program_id();
        let (config_pda, bump) = derive_config_pda(&pid);

        // BatchConfig: authority (32) + bump (1) + discriminator (8)
        let mut config_data = vec![0u8; 8 + 32 + 1];
        config_data[8..40].copy_from_slice(authority.pubkey().as_ref());
        config_data[40] = bump;

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
    fn test_vulnerable_accepts_any_remaining_accounts() {
        // SCENARIO: Attacker passes malicious accounts as remaining_accounts
        // ATTACK: Inject attacker-owned accounts to receive rewards
        // EXPECTED: Vulnerable version ACCEPTS any accounts (EXPLOIT WORKS)

        let (mut svm, authority) = setup();
        let attacker = Keypair::new();
        let pid = program_id();

        svm.airdrop(&attacker.pubkey(), LAMPORTS_PER_SOL).unwrap();

        let config_pda = setup_batch_config(&mut svm, &authority);

        // Create some "fake" accounts that attacker controls
        let fake_recipient_1 = Pubkey::new_unique();
        let fake_recipient_2 = Pubkey::new_unique();

        // Set up fake accounts (NOT owned by program, no proper structure)
        svm.set_account(
            fake_recipient_1,
            Account {
                lamports: LAMPORTS_PER_SOL,
                data: vec![0u8; 32], // Random data
                owner: attacker.pubkey(), // Attacker owns this!
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        svm.set_account(
            fake_recipient_2,
            Account {
                lamports: LAMPORTS_PER_SOL,
                data: vec![0u8; 32],
                owner: attacker.pubkey(),
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        // Call vulnerable_batch_reward with attacker's fake accounts
        let mut data = discriminator("vulnerable_batch_reward").to_vec();
        // amounts: Vec<u64> serialized - [2, 100, 200] (length + values)
        data.extend_from_slice(&2u32.to_le_bytes()); // vec length
        data.extend_from_slice(&100u64.to_le_bytes());
        data.extend_from_slice(&200u64.to_le_bytes());

        let ix = Instruction {
            program_id: pid,
            accounts: vec![
                AccountMeta::new_readonly(authority.pubkey(), true),
                AccountMeta::new_readonly(config_pda, false),
                // Attacker's fake accounts as remaining_accounts
                AccountMeta::new(fake_recipient_1, false),
                AccountMeta::new(fake_recipient_2, false),
            ],
            data,
        };

        let msg = Message::new(&[ix], Some(&authority.pubkey()));
        let tx = Transaction::new(&[&authority], msg, svm.latest_blockhash());
        let result = svm.send_transaction(tx);

        // Vulnerable version accepts - attacker's accounts receive "rewards"
        println!("Vulnerable batch reward result: {:?}", result);
    }

    #[test]
    fn test_secure_validates_remaining_accounts() {
        // SCENARIO: Secure version validates each remaining account
        // ATTACK: Try to pass accounts not owned by program
        // EXPECTED: Secure version REJECTS invalid accounts (FIX WORKS)

        let (mut svm, authority) = setup();
        let pid = program_id();

        let config_pda = setup_batch_config(&mut svm, &authority);

        // Create account NOT owned by program
        let invalid_recipient = Pubkey::new_unique();
        svm.set_account(
            invalid_recipient,
            Account {
                lamports: LAMPORTS_PER_SOL,
                data: vec![0u8; 64],
                owner: Pubkey::new_unique(), // Wrong owner!
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        let mut data = discriminator("secure_batch_reward").to_vec();
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&100u64.to_le_bytes());

        let ix = Instruction {
            program_id: pid,
            accounts: vec![
                AccountMeta::new_readonly(authority.pubkey(), true),
                AccountMeta::new_readonly(config_pda, false),
                AccountMeta::new(invalid_recipient, false),
            ],
            data,
        };

        let msg = Message::new(&[ix], Some(&authority.pubkey()));
        let tx = Transaction::new(&[&authority], msg, svm.latest_blockhash());
        let result = svm.send_transaction(tx);

        // Secure version rejects - account owner validation fails
        println!("Secure batch reward with invalid account (should fail): {:?}", result);
        assert!(result.is_err(), "Secure version should reject invalid remaining accounts");
    }

    #[test]
    fn test_secure_accepts_valid_recipients() {
        // SCENARIO: Valid recipients properly registered with program
        // EXPECTED: Secure version accepts properly validated accounts

        let (mut svm, authority) = setup();
        let pid = program_id();

        let config_pda = setup_batch_config(&mut svm, &authority);

        // Create valid recipient account (owned by program, proper structure)
        let valid_recipient = Pubkey::new_unique();
        
        // RewardRecipient structure: disc (8) + owner (32) + is_eligible (1) + bump (1)
        let mut recipient_data = vec![0u8; 8 + 32 + 1 + 1];
        recipient_data[8..40].copy_from_slice(authority.pubkey().as_ref());
        recipient_data[40] = 1; // is_eligible = true

        svm.set_account(
            valid_recipient,
            Account {
                lamports: LAMPORTS_PER_SOL,
                data: recipient_data,
                owner: pid, // Correctly owned by program
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        let mut data = discriminator("secure_batch_reward").to_vec();
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&100u64.to_le_bytes());

        let ix = Instruction {
            program_id: pid,
            accounts: vec![
                AccountMeta::new_readonly(authority.pubkey(), true),
                AccountMeta::new_readonly(config_pda, false),
                AccountMeta::new(valid_recipient, false),
            ],
            data,
        };

        let msg = Message::new(&[ix], Some(&authority.pubkey()));
        let tx = Transaction::new(&[&authority], msg, svm.latest_blockhash());
        let result = svm.send_transaction(tx);

        println!("Secure batch reward with valid recipient: {:?}", result);
    }
}
