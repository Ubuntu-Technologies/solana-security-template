# Contributing to Solana Security Template

This repository is an educational reference for building secure Solana programs. We welcome contributions that improve security awareness and code clarity.

## Development Setup

### Prerequisites

- Rust 1.89.0 or later
- Solana CLI 3.0.11 or later
- Anchor 0.32.1 or later
- Node.js 16+ (for TypeScript tests)

### Quick Start

```bash
# Clone the repository
git clone https://github.com/Ubuntu-Technologies/solana-security-template.git
cd solana-security-template

# Install dependencies
npm install
cargo build

# Run tests
anchor run test
```

### Build All Programs

To build all programs (including Pinocchio programs with SBF target):

```bash
anchor run build-all
```

This script:
1. Builds all Anchor programs
2. Builds Pinocchio programs with `cargo build-sbf`
3. Places compiled artifacts in `target/sbpf-solana-solana/`

### Run Tests

All tests use LiteSVM for fast, local testing without a validator:

```bash
# Run all tests
cd tests
cargo test

# Run specific test
cargo test test_vulnerable_missing_owner_check

# Run with output
cargo test -- --nocapture
```

## Adding a New Vulnerability Example

### Step 1: Create Program Structure

```bash
mkdir -p programs/my-vulnerability/src
cd programs/my-vulnerability
```

### Step 2: Create `Cargo.toml`

Reference existing programs in `programs/*/Cargo.toml` for the correct structure.

### Step 3: Implement Vulnerable & Secure Versions

- Create `src/vulnerable.rs` - Contains the broken code
- Create `src/secure.rs` - Contains the fixed code
- Create `src/lib.rs` - Routes between both versions

Each file must include:

- Clear header comments explaining what's being demonstrated
- Inline comments showing EXACTLY what changed
- Why the vulnerable version is dangerous
- How the secure version prevents the attack

Example structure:

```rust
//! VULNERABILITY: [Vulnerability Name]
//!
//! THE BUG:
//! - Line X: [specific problematic code]
//! - Impact: [what goes wrong]
//!
//! THE ATTACK:
//! 1. [Step 1]
//! 2. [Step 2]
//! 3. [Attacker wins by...]
//!
//! CATEGORY: [Critical/High/Medium]

pub fn vulnerable_instruction(...) -> ProgramResult {
    // Implementation
}
```

### Step 4: Create Tests

Tests must demonstrate BOTH the vulnerability AND the fix:

```rust
#[test]
fn test_vulnerable_[vulnerability_name]() {
    // SCENARIO: [What attacker wants to achieve]
    // ATTACK: [How attacker exploits the bug]
    // EXPECTED: Vulnerable version ACCEPTS the attack (EXPLOIT WORKS)
    
    // Setup
    let (mut svm, _) = setup();
    
    // Execute vulnerable instruction
    // Assert that it succeeds (vulnerability confirmed)
}

#[test]
fn test_secure_[vulnerability_name]() {
    // SCENARIO: [Same attack scenario]
    // ATTACK: [Same attack attempt]
    // EXPECTED: Secure version REJECTS the attack (FIX WORKS)
    
    // Setup
    let (mut svm, _) = setup();
    
    // Execute secure instruction
    // Assert that it fails (fix confirmed)
}
```

Add tests to `tests/` directory following the naming pattern `[vulnerability_name].rs`.

### Step 5: Document in README

Create `programs/my-vulnerability/README.md` with:

1. **Overview**: What this vulnerability is
2. **The Vulnerability**: How it works and why it's dangerous
3. **Attack Scenario**: Step-by-step attack narrative
4. **Attack Flow Diagram**: ASCII diagram showing vulnerable vs secure paths
5. **Files**: Description of vulnerable.rs and secure.rs
6. **Key Differences**: Side-by-side comparison
7. **Testing**: How to run tests and see the vulnerability/fix in action

### Step 6: Update Main Documentation

- Add entry to Vulnerability Matrix in [README.md](README.md)
- Note which framework(s) are used (Anchor/Pinocchio)

## Code Standards

### Naming Conventions

- Vulnerable functions: `vulnerable_[action_name](...)`
- Secure functions: `secure_[action_name](...)`
- Test functions: `test_vulnerable_[name]` and `test_secure_[name]`

### Comments

Every vulnerable code section must include:

```rust
// VULNERABLE: [Brief description]
// Bug: [What's wrong]
// Impact: [What can go wrong]
// Fixed in: secure.rs
```

### Testing

- All tests must pass with `anchor run test`
- Tests should use LiteSVM for fast execution
- Test names should clearly indicate what they demonstrate

## Documentation Standards

### README Structure

Each program README must include:

- [ ] Overview of vulnerability
- [ ] The bug (code example)
- [ ] Why it matters (impact)
- [ ] Attack scenario (step-by-step)
- [ ] Attack flow diagram (ASCII)
- [ ] Files and their purposes
- [ ] Key differences between versions
- [ ] Testing instructions

### Comments in Code

- Explain WHY code is vulnerable/secure, not just WHAT it does
- Include line-by-line comments for complex logic
- Add examples of how attacks work
- Show the fix and explain how it prevents attacks

## Submission Checklist

Before submitting a contribution:

- [ ] All tests pass: `anchor run test`
- [ ] No compiler warnings: `cargo build`
- [ ] Code follows naming conventions
- [ ] Vulnerable version is clearly marked
- [ ] Secure version is clearly marked
- [ ] Comments explain the vulnerability
- [ ] Tests demonstrate both exploit and fix
- [ ] README is complete and clear
- [ ] Vulnerability Matrix is updated
- [ ] No emojis in code comments or documentation

## Questions?

Refer to:
- [Solana Documentation](https://solana.com/docs)
- [Anchor Book](https://www.anchor-lang.com/docs)
- [Pinocchio Framework](https://github.com/anza-xyz/pinocchio)

## License

All contributions must be compatible with the MIT License.
