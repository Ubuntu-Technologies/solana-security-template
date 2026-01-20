//! Common utilities for security tests

pub fn load_program_id(name: &str) -> solana_pubkey::Pubkey {
    use solana_keypair::Keypair;
    use std::path::PathBuf;

    let keypair_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join(format!("target/deploy/{}-keypair.json", name));

    let keypair_bytes: Vec<u8> = serde_json::from_str(
        &std::fs::read_to_string(&keypair_path)
            .unwrap_or_else(|_| panic!("Failed to read {} keypair", name)),
    )
    .expect("Failed to parse keypair");

    use solana_signer::Signer;
    Keypair::from_bytes(&keypair_bytes).unwrap().pubkey()
}

pub fn load_program_bytes(name: &str) -> Vec<u8> {
    use std::path::PathBuf;

    let so_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join(format!("target/deploy/{}.so", name));

    std::fs::read(so_path).unwrap_or_else(|_| panic!("Failed to read {}.so", name))
}
