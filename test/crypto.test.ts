import { describe, it, expect } from 'vitest';
import {
  encryptPayload,
  decryptPayload,
  generatePassphrase,
  armorPayload,
  dearmorPayload
} from '../src/crypto.js';

describe('crypto module', () => {
  it('generates a 4-word passphrase', () => {
    const passphrase = generatePassphrase();
    const words = passphrase.split('-');
    expect(words).toHaveLength(4);
    for (const word of words) {
      expect(word.length).toBeGreaterThan(2);
    }
  });

  it('encrypts and decrypts correctly with the right passphrase', () => {
    const plaintext = 'DATABASE_URL=postgres://user:pass@host:5432/db\nAPI_KEY=sk_live_1234567890';
    const passphrase = generatePassphrase();

    const envelope = encryptPayload(plaintext, passphrase, { filename: '.env' });
    expect(envelope.algo).toBe('aes-256-gcm');
    expect(envelope.ciphertext).toBeDefined();

    const decrypted = decryptPayload(envelope, passphrase);
    expect(decrypted).toBe(plaintext);
  });

  it('fails decryption with wrong passphrase', () => {
    const plaintext = 'SECRET_TOKEN=xyz123';
    const envelope = encryptPayload(plaintext, 'correct-passphrase-here');

    expect(() => {
      decryptPayload(envelope, 'wrong-passphrase-attempt');
    }).toThrow(/Decryption failed/);
  });

  it('armors and dearmors payloads to carry:// format', () => {
    const plaintext = 'STRIPE_KEY=sk_test_51...';
    const passphrase = 'test-secret-key';
    const envelope = encryptPayload(plaintext, passphrase);

    const armored = armorPayload(envelope);
    expect(armored.startsWith('carry://')).toBe(true);

    const dearmoredEnvelope = dearmorPayload(armored);
    expect(dearmoredEnvelope.ciphertext).toBe(envelope.ciphertext);

    const decrypted = decryptPayload(dearmoredEnvelope, passphrase);
    expect(decrypted).toBe(plaintext);
  });
});
