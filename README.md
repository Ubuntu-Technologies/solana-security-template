# Solana Security Template

A comprehensive collection of Solana programs demonstrating common vulnerabilities and their fixes. Each program includes vulnerable and secure implementations with tests.

## How to Use This Repository

### For Learners
1. Start with [owner-check](programs/owner-check/) - simplest vulnerability
2. Read the vulnerable code with comments
3. Read the secure code with comments
4. Run tests to see the exploit fail and fix succeed
5. Move to next program

### For Reviewers
- Each program follows the same structure: vulnerable → secure
- Tests demonstrate both exploit and fix
- Comments explain the reasoning, not just the code

### Quick Checklist
Before auditing a program, verify:
- [ ] Vulnerable code is clearly marked
- [ ] Secure code includes the fix
- [ ] Tests pass for both versions
- [ ] Comments explain the attack

## Requirements

- Rust 1.89.0
- Solana CLI 3.0.11
- Anchor 0.32.1

## Setup

```bash
# Clone
git clone https://github.com/Ubuntu-Technologies/solana-security-template.git
cd solana-security-template

# Build all programs
anchor run build-all

# Run tests
anchor run test
```

## Vulnerability Coverage Matrix

| Vulnerability | Program | Risk | Anchor | Pinocchio | Fix Strategy |
|--------------|---------|------|--------|-----------|--------------|
| Missing Signer Check | [signer-authorization](programs/signer-authorization/) | Critical | Yes | - | Use `Signer<'info>` type |
| Integer Overflow | [arithmetic-overflow](programs/arithmetic-overflow/) | Critical | Yes | - | Use `checked_*` methods |
| Missing Owner Check | [owner-check](programs/owner-check/) | Critical | - | Yes | Verify `account.owner == program_id` |
| Weak PDA Seeds | [pda-security](programs/pda-security/) | High | Yes | - | Include user key + nonce in seeds |
| Account Revival | [account-close](programs/account-close/) | High | Yes | - | Zero data before close |
| Type Cosplay | [account-type-mismatch](programs/account-type-mismatch/) | High | - | Yes | Add discriminator byte |
| Missing Validation | [p-escrow](programs/p-escrow/) | High | - | Yes | Verify caller matches stored data |
| Duplicate Accounts | [duplicate-accounts](programs/duplicate-accounts/) | High | Yes | - | Add `key() != key()` constraint |
| Insecure Init | [insecure-init](programs/insecure-init/) | High | Yes | - | Use `init` or check `is_initialized` |
| Stale Data After CPI | [account-reloading](programs/account-reloading/) | Medium | Yes | - | Call `reload()` after CPI |
| Unvalidated Remaining | [remaining-accounts](programs/remaining-accounts/) | Medium | Yes | - | Validate owner/type manually |
| Insecure Authority | [authority-transfer](programs/authority-transfer/) | Critical | Yes | - | Two-step propose/accept pattern |
| Multiple Combined | [amm](programs/amm/) | Critical | Yes | - | All of the above |

## Quick Reference

### 1. Missing Signer Check
```rust
// ❌ VULNERABLE          // ✅ SECURE
pub authority: AccountInfo  →  pub authority: Signer
```

### 2. Arithmetic Overflow
```rust
// ❌ VULNERABLE          // ✅ SECURE
let r = a * b;           →  let r = a.checked_mul(b)?;
```

### 3. Missing Owner Check
```rust
// ❌ VULNERABLE          // ✅ SECURE
let data = acc.data();   →  require!(acc.owner == program_id);
```

### 4. Weak PDA Seeds
```rust
// ❌ VULNERABLE          // ✅ SECURE
seeds = [b"config"]      →  seeds = [b"config", user.key(), &nonce]
```

### 5. Account Revival
```rust
// ❌ VULNERABLE          // ✅ SECURE
acc.lamports = 0;        →  acc.data.fill(0); acc.close(dest)?;
```

### 6. Type Cosplay
```rust
// ❌ VULNERABLE          // ✅ SECURE
struct User { bal: u64 } →  struct User { disc: u8, bal: u64 }
```

### 7. Missing Refund Validation
```rust
// ❌ VULNERABLE          // ✅ SECURE
let dest = accounts[3];  →  require!(caller == escrow.maker);
```

### 8. Duplicate Mutable Accounts
```rust
// ❌ VULNERABLE          // ✅ SECURE
#[account(mut)] from,to  →  constraint = from.key() != to.key()
```

### 9. Insecure Initialization
```rust
// ❌ VULNERABLE          // ✅ SECURE
init_if_needed           →  init OR check is_initialized
```

### 10. Stale Data After CPI
```rust
// ❌ VULNERABLE          // ✅ SECURE
cpi_call()?; use(acc);   →  cpi_call()?; acc.reload()?; use(acc);
```

### 11. Unvalidated Remaining Accounts
```rust
// ❌ VULNERABLE          // ✅ SECURE
for a in remaining { }   →  require!(a.owner == program_id);
```

### 12. Insecure Authority Transfer
```rust
// ❌ VULNERABLE          // ✅ SECURE
cfg.authority = new;     →  cfg.pending = new; (then accept step)
```

## Project Structure

```
programs/
├── signer-authorization/  # Missing signer check
├── arithmetic-overflow/   # Integer overflow
├── owner-check/          # Missing owner check (Pinocchio)
├── pda-security/         # Weak PDA seeds
├── account-close/        # Account revival
├── account-type-mismatch/# Type cosplay (Pinocchio)
├── p-escrow/             # Refund validation (Pinocchio)
├── duplicate-accounts/   # Duplicate accounts
├── insecure-init/        # Re-initialization
├── account-reloading/    # Stale data after CPI
├── remaining-accounts/   # Unvalidated remaining
├── authority-transfer/   # Insecure admin transfer
└── amm/
    ├── buggy-amm/        # All vulnerabilities combined
    └── secure-amm/       # Fixed implementation
```

Each program directory contains:
- `README.md` - Detailed vulnerability explanation
- `src/lib.rs` - Program entry points  
- `src/vulnerable.rs` - Vulnerable implementation
- `src/secure.rs` - Fixed implementation

## Versions

| Component | Version |
|-----------|---------|
| Rust | 1.89.0 |
| Solana CLI | 3.0.11 |
| Anchor | 0.32.1 |
| Pinocchio | 0.9.2 / 0.10 |
| LiteSVM | 0.6.1 |

## License

MIT

