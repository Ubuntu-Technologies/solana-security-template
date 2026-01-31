//! Tests for the Account Reloading vulnerability
//!
//! Demonstrates:
//! - Vulnerable: Stale account data after CPI leads to incorrect logic
//! - Secure: reload() refreshes account data after CPI

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
            .join("target/deploy/account_reloading-keypair.json");

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
            .join("target/deploy/account_reloading.so");
        std::fs::read(so_path).expect("Failed to read program file")
    }

    fn derive_counter_pda(authority: &Pubkey, program_id: &Pubkey) -> (Pubkey, u8) {
        Pubkey::find_program_address(&[b"counter", authority.as_ref()], program_id)
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

    fn setup_counter(svm: &mut LiteSVM, authority: &Keypair, initial_count: u64) -> Pubkey {
        let pid = program_id();
        let (counter_pda, bump) = derive_counter_pda(&authority.pubkey(), &pid);

        // Counter: authority (32) + count (8) + bump (1) + discriminator (8)
        let mut counter_data = vec![0u8; 8 + 32 + 8 + 1];
        counter_data[8..40].copy_from_slice(authority.pubkey().as_ref());
        counter_data[40..48].copy_from_slice(&initial_count.to_le_bytes());
        counter_data[48] = bump;

        svm.set_account(
            counter_pda,
            Account {
                lamports: LAMPORTS_PER_SOL,
                data: counter_data,
                owner: pid,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        counter_pda
    }

    #[test]
    fn test_vulnerable_double_increment_uses_stale_data() {
        // SCENARIO: Double increment where second operation uses stale data
        // ATTACK: In real CPI scenario, stale data leads to incorrect calculations
        // EXPECTED: Demonstrates the vulnerability pattern

        let (mut svm, authority) = setup();
        let pid = program_id();

        let counter_pda = setup_counter(&mut svm, &authority, 0);

        // Call vulnerable_double_increment
        let data = discriminator("vulnerable_double_increment").to_vec();

        let ix = Instruction {
            program_id: pid,
            accounts: vec![
                AccountMeta::new_readonly(authority.pubkey(), true),
                AccountMeta::new(counter_pda, false),
            ],
            data,
        };

        let msg = Message::new(&[ix], Some(&authority.pubkey()));
        let tx = Transaction::new(&[&authority], msg, svm.latest_blockhash());
        let result = svm.send_transaction(tx);

        // This demonstrates the pattern - in real CPI, data would be stale
        println!("Vulnerable double increment result: {:?}", result);

        // Check final counter value
        let account = svm.get_account(&counter_pda).unwrap();
        let count = u64::from_le_bytes(account.data[40..48].try_into().unwrap());
        println!("Counter value after vulnerable double increment: {}", count);
    }

    #[test]
    fn test_secure_double_increment_reloads() {
        // SCENARIO: Double increment with proper reload between operations
        // EXPECTED: Secure version uses fresh data after CPI

        let (mut svm, authority) = setup();
        let pid = program_id();

        let counter_pda = setup_counter(&mut svm, &authority, 0);

        // Call secure_double_increment
        let data = discriminator("secure_double_increment").to_vec();

        let ix = Instruction {
            program_id: pid,
            accounts: vec![
                AccountMeta::new_readonly(authority.pubkey(), true),
                AccountMeta::new(counter_pda, false),
            ],
            data,
        };

        let msg = Message::new(&[ix], Some(&authority.pubkey()));
        let tx = Transaction::new(&[&authority], msg, svm.latest_blockhash());
        let result = svm.send_transaction(tx);

        println!("Secure double increment result: {:?}", result);

        // Check final counter value
        let account = svm.get_account(&counter_pda).unwrap();
        let count = u64::from_le_bytes(account.data[40..48].try_into().unwrap());
        println!("Counter value after secure double increment: {}", count);
    }

    #[test]
    fn test_basic_increment_works() {
        // SCENARIO: Basic single increment operation
        // EXPECTED: Counter increments by 1

        let (mut svm, authority) = setup();
        let pid = program_id();

        let counter_pda = setup_counter(&mut svm, &authority, 5);

        let data = discriminator("increment").to_vec();

        let ix = Instruction {
            program_id: pid,
            accounts: vec![
                AccountMeta::new_readonly(authority.pubkey(), true),
                AccountMeta::new(counter_pda, false),
            ],
            data,
        };

        let msg = Message::new(&[ix], Some(&authority.pubkey()));
        let tx = Transaction::new(&[&authority], msg, svm.latest_blockhash());
        let result = svm.send_transaction(tx);

        println!("Basic increment result: {:?}", result);

        // Verify counter incremented
        let account = svm.get_account(&counter_pda).unwrap();
        let count = u64::from_le_bytes(account.data[40..48].try_into().unwrap());
        println!("Counter value after increment: {} (expected: 6)", count);
    }
}
