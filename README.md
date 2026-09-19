# env-carry

> **Zero-friction, end-to-end encrypted environment transfer, drift detection, and takeover audit for developers.**

Sharing `.env` files over Slack, Telegram, WhatsApp, or email is an insecure anti-pattern that constantly bites teams. Meanwhile, enterprise vaults (Doppler, HashiCorp Vault, 1Password) require account setups, paid subscriptions, and configuration overhead that get in the way during a fast-moving codebase takeover, contractor handoff, or lean startup launch.

**env-carry** bridges this gap: **enterprise-grade AES-256-GCM encryption with zero setup, zero accounts, and developer-native CLI workflows.**

---

## Features

- **Zero-Knowledge E2EE**: AES-256-GCM encryption with scrypt key derivation. Only holders of the passphrase can decrypt.
- **Zero Accounts / Zero Setup**: Run via `npx env-carry` or local install. No cloud dashboards, no credit cards.
- **One-Command Ephemeral Transit (`send` / `receive`)**: One-shot peer transit with automatic burn-after-reading.
- **Copyable Armor Codes (`carry://...`)**: Safe to paste anywhere, even into unencrypted chat channels, because the payload is fully encrypted ciphertext.
- **Codebase Takeover Auditor (`audit`)**:
  - Automatically identifies credentials from 30+ providers (Supabase, Stripe, OpenAI, Resend, AWS, GitHub, Twilio, etc.).
  - Generates an actionable **Post-Takeover Key Rotation Checklist** with direct dashboard rotation links.
  - **Git History Leak Scanner**: Inspects commit history to verify if current secrets were ever accidentally committed in the past.
- **Drift and Schema Verification (`check`)**: Compares `.env` against `.env.example` to detect missing variables and unconfigured placeholders before booting projects.
- **Memory-Only In-Memory Runner (`run`)**: Injects decrypted secrets directly into process memory (`env-carry run -- npm run dev`) without writing plaintext files to disk.
- **Git-Native Versioning (`seal` / `unseal`)**: Safely commit encrypted `.env.carry` files to Git.

---

## Quickstart

### Run with npx (No installation required)
```bash
npx env-carry --help
```

### Or install globally
```bash
npm install -g env-carry
```

---

## Usage and Commands

### 1. Codebase Takeover Audit
When inheriting a project, assume previous contributors still have active credentials. Run an audit to generate a rotation checklist and check for git leaks:

```bash
env-carry audit .env
```

Output:
- Detailed breakdown of all detected service keys by severity (`CRITICAL`, `HIGH`, `MEDIUM`).
- Direct dashboard links to rotate each key.
- Warning if any active secret was found in Git commit history.
- Automatically generates `TAKEOVER_CHECKLIST.md`.

---

### 2. Ephemeral Transit (`send` and `receive`)
Handing over a `.env` to another developer on your local network:

```bash
# Sender:
env-carry send .env

# Output:
# Passphrase: amber-beacon-summit-oasis
# Option A: carry://eyJh... (copy-pasteable armor code)
# Option B: Run on recipient machine:
#   env-carry receive http://192.168.1.15:52341/carry
```

On recipient machine:
```bash
env-carry receive http://192.168.1.15:52341/carry
# Decrypts in-memory, saves to .env, and burns the sender relay instantly!
```

---

### 3. Encrypted Armor Codes (`pack` and `unpack`)
Need to send an environment asynchronously?

```bash
# Pack into a safe one-line armor code:
env-carry pack .env --armor

# Output:
# Passphrase: coral-beacon-pulse-summit
# carry://eyJ2ZXJzaW9uIjoxLCJhbGdvIjoiYWVzLTI1Ni...
```

You can safely paste the `carry://` string anywhere. Without the 4-word passphrase, it is impossible to decrypt.

On the other side:
```bash
env-carry unpack "carry://eyJ2ZXJzaW9uIjoxLCJhbGdv..." -p "coral-beacon-pulse-summit"
```

---

### 4. Configuration Drift Detection (`check`)
Make sure your active `.env` matches the project template before debugging runtime crashes:

```bash
env-carry check .env -e .env.example
```

Detects:
- Missing keys defined in the template.
- Unedited placeholder values (e.g. `your_api_key_here`, `TODO`, `xxx`).
- Empty variables.

---

### 5. In-Memory Execution (`run`)
Prevent malicious npm packages or accidental `git add .` from exposing your keys:

```bash
# Encrypt your local env into a sealed file:
env-carry seal .env

# Run your app directly with memory injection (no plaintext file on disk!):
env-carry run -f .env.carry -- npm run dev
```

---

## Cryptography Specification

| Layer | Implementation |
| :--- | :--- |
| **Cipher** | AES-256-GCM (Galois/Counter Mode with 96-bit random IV) |
| **Key Derivation** | scrypt (N=16384, r=8, p=1) with 128-bit cryptographically secure random salt |
| **Integrity / Authentication** | 128-bit authentication tag (`authTag`), preventing tampering or bit-flipping attacks |
| **Passphrase Entropy** | 4-word mnemonic generated using high-entropy CSPRNG (`crypto.randomBytes`) |
| **Armor Format** | `carry://<base64url-encoded-envelope>` |

---

## Testing

```bash
npm test
```

Includes unit tests for crypto roundtrips, wrong-key authentication failures, parser edge cases, secret pattern detectors, and drift detection.

---

## License

MIT (c) 2026
