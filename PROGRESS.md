# Solana Security Template - Progress Tracker

## Status: 9 PROGRAMS, 28 TESTS PASSING

---

## Programs

| # | Name | Framework | Vulnerability | Tests |
|---|------|-----------|---------------|-------|
| 1 | signer-authorization | Anchor | Missing signer check | 3 |
| 2 | arithmetic-overflow | Anchor | Unchecked u64 math | 3 |
| 3 | owner-check | Pinocchio | Missing owner validation | 3 |
| 4 | pda-seeds | Anchor | Weak seeds / bump | 4 |
| 5 | account-close | Anchor | Revival attack | 3 |
| 6 | account-type-mismatch | Pinocchio | Missing discriminator | 3 |
| 7 | p-escrow | Pinocchio | Missing refund validation | 3 |
| 8 | buggy-amm | Anchor | All vulnerabilities combined | 3 |
| 9 | secure-amm | Anchor | Fixed version | 3 |

---

## Build

```bash
anchor build
cd programs/owner-check && cargo build-sbf
cd programs/account-type-mismatch && cargo build-sbf
cd programs/p-escrow && cargo build-sbf
cd programs/amm/buggy-amm && cargo build-sbf
cd programs/amm/secure-amm && cargo build-sbf
```

## Test

```bash
cd tests && cargo test
```

---

## Completed

- [x] All 9 programs built
- [x] All 28 tests passing
- [x] README.md with setup and docs
