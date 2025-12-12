# Stacks Biometric Vault

A cutting-edge smart contract wallet secured by biometric authentication using **Clarity 4's `secp256r1-verify`** function. This enables passwordless, phishing-resistant authentication via passkeys, Face ID, Touch ID, and other WebAuthn-compatible methods.

## Why This Matters

Traditional crypto wallets rely on seed phrases and private keys that can be:
- Lost or forgotten
- Stolen through phishing
- Compromised if stored insecurely
- Difficult for non-technical users

**Biometric authentication solves this** by:
- Using your face, fingerprint, or security key
- Storing credentials securely in device hardware (TPM/Secure Enclave)
- Enabling familiar authentication methods
- Providing phishing resistance built into the protocol

## Clarity 4 Feature: secp256r1-verify

This project showcases Clarity 4's **`secp256r1-verify`** function, which:
- Verifies secp256r1 (P-256) ECDSA signatures on-chain
- Enables WebAuthn/FIDO2 passkey verification
- Supports biometric authentication directly in smart contracts
- Uses the same curve as Apple Secure Enclave and Android KeyStore

### Technical Details

The `secp256r1-verify` function takes:
- A 32-byte message hash
- A public key (33-byte compressed or 65-byte uncompressed)
- A signature (64 or 65 bytes)

Returns `true` if the signature is valid, `false` otherwise.

```clarity
(secp256r1-verify message-hash public-key signature)
```

## Project Architecture

### 1. **Biometric Auth Contract** (`biometric-auth.clar`)
- Manages passkey registration and verification
- Uses `secp256r1-verify` for signature validation
- Stores public keys associated with wallet owners
- Supports multiple passkeys per wallet

### 2. **Vault Contract** (`vault.clar`)
- Holds STX and SIP-010 tokens
- Requires biometric authentication for withdrawals
- Integrates with the auth contract
- Supports transaction batching

### 3. **Recovery Contract** (`recovery.clar`)
- Guardian-based recovery system
- Allows adding/removing trusted guardians
- Time-delayed recovery process
- Emergency fallback for lost devices

## Features

- **Passkey Authentication**: Sign transactions with Face ID/Touch ID
- **Multiple Devices**: Register multiple passkeys per wallet
- **Social Recovery**: Guardian-based account recovery
- **STX & Token Support**: Hold and transfer any SIP-010 token
- **Batch Transactions**: Execute multiple operations in one signature
- **Time Locks**: Optional time delays for large withdrawals
- **Revocation**: Instantly revoke compromised passkeys

## Use Cases

1. **Consumer Wallets**: User-friendly crypto wallets for mainstream adoption
2. **Corporate Treasury**: Multi-device authentication for company funds
3. **DeFi Integration**: Secure access to DeFi protocols with biometrics
4. **DAO Governance**: Biometric voting and proposal signing
5. **NFT Marketplaces**: Secure NFT trading with passkeys

## How It Works

### 1. Wallet Creation
```
User → Create Passkey (Face ID/Touch ID)
     → Browser generates key pair in Secure Enclave
     → Public key sent to blockchain
     → Vault contract deployed with user's public key
```

### 2. Transaction Signing
```
User → Initiate transaction
     → Biometric prompt (Face ID/Touch ID)
     → Device signs message with private key
     → Signature sent to blockchain
     → Contract verifies with secp256r1-verify
     → Transaction executes if valid
```

### 3. Account Recovery
```
User → Lost device
     → Contact guardians
     → Guardians approve recovery
     → Time delay passes
     → New passkey registered
     → Old passkey revoked
```

## Security Model

### Hardware Security
- Private keys never leave device hardware
- Stored in TPM/Secure Enclave
- Biometric gating before any operation
- Cannot be extracted or copied

### On-Chain Security
- Signature verification via secp256r1-verify
- Public key authentication
- Time-delayed recovery
- Guardian consensus requirements

### Threat Protection
- **Phishing**: Impossible - passkeys are domain-bound
- **Stolen Device**: Requires biometric to unlock
- **Lost Device**: Social recovery via guardians
- **Compromised Passkey**: Instant revocation capability

## Development Roadmap

### Phase 1: Core Contracts (Current)
- [x] Project setup
- [ ] Biometric auth contract with secp256r1-verify
- [ ] Vault contract for asset management
- [ ] Recovery contract with guardian system

### Phase 2: Testing & Security
- [ ] Comprehensive test suite
- [ ] Edge case coverage
- [ ] Security audit preparation
- [ ] Testnet deployment

### Phase 3: Integration
- [ ] JavaScript/TypeScript SDK
- [ ] WebAuthn helper library
- [ ] Example frontend implementation
- [ ] API documentation

### Phase 4: Advanced Features
- [ ] Multi-signature support
- [ ] Hardware key integration (YubiKey)
- [ ] Transaction policies and limits
- [ ] Spending allowances

## Builder Challenge Highlights

This project demonstrates:
- **Primary Clarity 4 Feature**: `secp256r1-verify` for passkey authentication
- **Innovation**: First-class biometric wallet on Stacks
- **User Impact**: Makes crypto accessible to mainstream users
- **Technical Depth**: Complex cryptographic verification on-chain
- **Practical Use**: Real-world application with immediate utility

## Technical Requirements

- Clarinet >= 1.0.0
- Deno (for tests)
- Node.js >= 16 (for examples)
- Modern browser with WebAuthn support

## Getting Started

```bash
# Clone repository
git clone <your-repo-url>
cd stacks-biometric-vault

# Check contracts
clarinet check

# Run tests
clarinet test

# Start console
clarinet console
```

## Project Status

🚧 **Under Active Development** - Building incrementally with feature branches

Current branch: `feature/project-setup`

## Resources

- [Clarity 4 Documentation](https://docs.stacks.co/whats-new/clarity-4-is-now-live)
- [WebAuthn Guide](https://webauthn.guide/)
- [secp256r1 Curve Spec](https://www.secg.org/sec2-v2.pdf)
- [FIDO Alliance](https://fidoalliance.org/)

## License

MIT License - See LICENSE file

## Contributing

See CONTRIBUTING.md for guidelines. We welcome contributions in:
- Smart contract development
- Security auditing
- Frontend integration
- Documentation

---

Built for the Stacks Builder Challenge - Showcasing Clarity 4's cutting-edge authentication capabilities
