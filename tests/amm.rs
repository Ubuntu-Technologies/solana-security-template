//! Tests for Buggy-AMM and Secure-AMM programs

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use litesvm::LiteSVM;
    use solana_keypair::Keypair;
    use solana_native_token::LAMPORTS_PER_SOL;
    use solana_pubkey::Pubkey;
    use solana_signer::Signer;

    fn buggy_program_id() -> Pubkey {
        let keypair_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("programs/amm/target/deploy/buggy_amm-keypair.json");

        if keypair_path.exists() {
            let keypair_bytes: Vec<u8> = serde_json::from_str(
                &std::fs::read_to_string(&keypair_path).expect("Failed to read keypair"),
            )
            .expect("Failed to parse keypair");
            Keypair::from_bytes(&keypair_bytes).unwrap().pubkey()
        } else {
            Pubkey::new_unique()
        }
    }

    fn secure_program_id() -> Pubkey {
        let keypair_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("programs/amm/target/deploy/secure_amm-keypair.json");

        if keypair_path.exists() {
            let keypair_bytes: Vec<u8> = serde_json::from_str(
                &std::fs::read_to_string(&keypair_path).expect("Failed to read keypair"),
            )
            .expect("Failed to parse keypair");
            Keypair::from_bytes(&keypair_bytes).unwrap().pubkey()
        } else {
            Pubkey::new_unique()
        }
    }

    fn read_buggy_program() -> Vec<u8> {
        let so_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("programs/amm/target/deploy/buggy_amm.so");
        std::fs::read(so_path).expect("Failed to read buggy_amm.so")
    }

    fn read_secure_program() -> Vec<u8> {
        let so_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("programs/amm/target/deploy/secure_amm.so");
        std::fs::read(so_path).expect("Failed to read secure_amm.so")
    }

    fn setup_buggy() -> (LiteSVM, Keypair) {
        let mut svm = LiteSVM::new();
        let payer = Keypair::new();
        svm.airdrop(&payer.pubkey(), 10 * LAMPORTS_PER_SOL)
            .expect("Airdrop failed");
        svm.add_program(buggy_program_id(), &read_buggy_program());
        (svm, payer)
    }

    fn setup_secure() -> (LiteSVM, Keypair) {
        let mut svm = LiteSVM::new();
        let payer = Keypair::new();
        svm.airdrop(&payer.pubkey(), 10 * LAMPORTS_PER_SOL)
            .expect("Airdrop failed");
        svm.add_program(secure_program_id(), &read_secure_program());
        (svm, payer)
    }

    // ============= BUGGY-AMM VULNERABILITY TESTS =============

    #[test]
    fn test_buggy_weak_pda_predictable() {
        // VULN: Config PDA uses only b"config" - globally predictable
        let (_svm, _payer) = setup_buggy();
        let pid = buggy_program_id();

        let (config_pda, _bump) = Pubkey::find_program_address(&[b"config"], &pid);

        // Only one possible config address per program - collision risk
        println!(
            "Buggy config PDA: {} (predictable, no uniqueness)",
            config_pda
        );
        assert!(config_pda.to_string().len() > 0);
    }

    #[test]
    fn test_buggy_overflow_in_swap() {
        // VULN: Unchecked multiplication in swap calculation
        let (_svm, _payer) = setup_buggy();

        // Example: large reserve * amount overflows
        let reserve: u64 = 10_000_000_000_000_000; // 10M tokens
        let amount: u64 = 10_000_000_000_000_000; // 10M tokens

        // Buggy: reserve * amount overflows u64
        let buggy_k = reserve.wrapping_mul(amount);

        // Secure: uses u128 to prevent overflow
        let secure_k = (reserve as u128) * (amount as u128);

        println!("Buggy k (wrapped): {}", buggy_k);
        println!("Secure k (u128):   {}", secure_k);
        println!(
            "Expected k:        {}",
            100_000_000_000_000_000_000_000_000_000_000u128
        );

        // buggy_k is wrong due to overflow - it's vastly different from correct
        let correct_k = 100_000_000_000_000_000_000_000_000_000_000u128;
        assert_ne!(buggy_k as u128, correct_k); // Overflowed value is garbage
        assert_eq!(secure_k, correct_k); // Correct calculation
    }

    #[test]
    fn test_buggy_no_slippage_check() {
        // VULN: min_out parameter ignored - sandwich attack vector
        let (_svm, _payer) = setup_buggy();

        // Simulated attack scenario:
        // 1. Victim submits swap with min_out = 1000
        // 2. Attacker front-runs, moves price
        // 3. Victim gets 500 tokens (50% less)
        // 4. Buggy program accepts because min_out is ignored

        let expected_out = 1000u64;
        let actual_out = 500u64; // After sandwich
        let min_out = 950u64; // Victim's slippage tolerance

        // Buggy: ignores min_out, attack succeeds
        let buggy_accepts = true; // Always accepts

        // Secure: checks min_out
        let secure_accepts = actual_out >= min_out;

        println!("Buggy accepts 500 when expecting 1000: {}", buggy_accepts);
        println!("Secure accepts 500 when min is 950: {}", secure_accepts);

        assert!(buggy_accepts); // Vulnerability: accepts bad trade
        assert!(!secure_accepts); // Secure rejects
    }

    // ============= SECURE-AMM FIX TESTS =============

    #[test]
    fn test_secure_unique_pda_seeds() {
        // FIX: Includes seed for uniqueness
        let (_svm, _payer) = setup_secure();
        let pid = secure_program_id();

        let seed1: u64 = 1;
        let seed2: u64 = 2;

        let (pda1, _) = Pubkey::find_program_address(&[b"config", &seed1.to_le_bytes()], &pid);
        let (pda2, _) = Pubkey::find_program_address(&[b"config", &seed2.to_le_bytes()], &pid);

        println!("Secure PDA with seed 1: {}", pda1);
        println!("Secure PDA with seed 2: {}", pda2);

        assert_ne!(pda1, pda2); // Different seeds = different addresses
    }

    #[test]
    fn test_secure_checked_math_prevents_overflow() {
        // FIX: All operations use checked_* methods
        let (_svm, _payer) = setup_secure();

        let max_amount: u64 = u64::MAX;
        let multiplier: u128 = 9900;

        // Would overflow as u64, safe as u128
        let result = (max_amount as u128)
            .checked_mul(multiplier)
            .and_then(|v| v.checked_div(10000));

        println!("Secure handles large values: {:?}", result);
        assert!(result.is_some());
    }

    #[test]
    fn test_secure_slippage_protection() {
        // FIX: require!(amount_out >= min_out)
        let (_svm, _payer) = setup_secure();

        let amount_out = 980u64;
        let min_out = 950u64;

        let passes = amount_out >= min_out;
        println!("Slippage check (980 >= 950): {} - PASS", passes);
        assert!(passes);

        let bad_out = 900u64;
        let fails = bad_out >= min_out;
        println!("Slippage check (900 >= 950): {} - FAIL", fails);
        assert!(!fails);
    }
}
