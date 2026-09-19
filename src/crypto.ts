import crypto from 'node:crypto';

export interface EncryptedEnvelope {
  version: 1;
  algo: 'aes-256-gcm';
  kdf: 'scrypt';
  salt: string; // hex
  iv: string; // hex
  tag: string; // hex
  ciphertext: string; // hex
  metadata?: {
    filename?: string;
    keyCount?: number;
    createdAt: string;
  };
}

const WORDLIST = [
  'amber', 'anchor', 'arcade', 'arrow', 'atlas', 'aurora', 'beacon', 'breeze',
  'bridge', 'cactus', 'canyon', 'cedar', 'cliff', 'clover', 'comet', 'coral',
  'crater', 'crystal', 'delta', 'dune', 'eagle', 'echo', 'ember', 'falcon',
  'feather', 'flame', 'forest', 'fossil', 'galaxy', 'glacier', 'grove', 'harbor',
  'haven', 'horizon', 'island', 'jasper', 'jungle', 'lagoon', 'lantern', 'lark',
  'legacy', 'matrix', 'meadow', 'meteor', 'monarch', 'nebula', 'oasis', 'ocean',
  'orbit', 'osprey', 'pebble', 'phoenix', 'pillar', 'planet', 'prism', 'pulse',
  'quarry', 'quartz', 'radar', 'radiant', 'ranger', 'raven', 'reef', 'ripple',
  'river', 'ruby', 'safari', 'sailor', 'saturn', 'shadow', 'shield', 'sierra',
  'signal', 'silver', 'solar', 'spark', 'summit', 'sunset', 'tactic', 'timber',
  'titan', 'topaz', 'trail', 'tundra', 'valley', 'vector', 'velvet', 'vortex',
  'voyage', 'willow', 'zenith', 'zephyr'
];

/**
 * Generate a memorable, high-entropy 4-word passphrase.
 * E.g. "coral-beacon-pulse-summit"
 */
export function generatePassphrase(): string {
  const words: string[] = [];
  const randomBytes = crypto.randomBytes(8);
  for (let i = 0; i < 4; i++) {
    const index = randomBytes.readUInt16BE(i * 2) % WORDLIST.length;
    words.push(WORDLIST[index]);
  }
  return words.join('-');
}

/**
 * Derive a 256-bit encryption key using scrypt.
 */
function deriveKey(passphrase: string, salt: Buffer): Buffer {
  return crypto.scryptSync(passphrase.normalize('NFKD'), salt, 32, {
    N: 16384,
    r: 8,
    p: 1,
    maxmem: 32 * 1024 * 1024
  });
}

/**
 * Encrypt arbitrary text using AES-256-GCM.
 */
export function encryptPayload(
  plaintext: string,
  passphrase: string,
  metadata?: { filename?: string; keyCount?: number }
): EncryptedEnvelope {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12); // 96-bit IV recommended for GCM
  const key = deriveKey(passphrase, salt);

  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final()
  ]);
  const tag = cipher.getAuthTag();

  return {
    version: 1,
    algo: 'aes-256-gcm',
    kdf: 'scrypt',
    salt: salt.toString('hex'),
    iv: iv.toString('hex'),
    tag: tag.toString('hex'),
    ciphertext: ciphertext.toString('hex'),
    metadata: {
      ...metadata,
      createdAt: new Date().toISOString()
    }
  };
}

/**
 * Decrypt an EncryptedEnvelope using AES-256-GCM.
 * Throws an error if the passphrase is incorrect or data was tampered with.
 */
export function decryptPayload(
  envelope: EncryptedEnvelope,
  passphrase: string
): string {
  if (envelope.version !== 1 || envelope.algo !== 'aes-256-gcm') {
    throw new Error(`Unsupported envelope format or algorithm (${envelope.algo})`);
  }

  const salt = Buffer.from(envelope.salt, 'hex');
  const iv = Buffer.from(envelope.iv, 'hex');
  const tag = Buffer.from(envelope.tag, 'hex');
  const ciphertext = Buffer.from(envelope.ciphertext, 'hex');
  const key = deriveKey(passphrase, salt);

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);

  try {
    const decrypted = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final()
    ]);
    return decrypted.toString('utf8');
  } catch {
    throw new Error('Decryption failed: incorrect passphrase or corrupted data');
  }
}

const ARMOR_PREFIX = 'carry://';

/**
 * Encode envelope into a compact, single-line URL-safe armor string.
 */
export function armorPayload(envelope: EncryptedEnvelope): string {
  const json = JSON.stringify(envelope);
  const base64url = Buffer.from(json, 'utf8')
    .toString('base64url');
  return `${ARMOR_PREFIX}${base64url}`;
}

/**
 * Decode an armor string or raw JSON back to an EncryptedEnvelope.
 */
export function dearmorPayload(armoredText: string): EncryptedEnvelope {
  const trimmed = armoredText.trim();
  if (trimmed.startsWith(ARMOR_PREFIX)) {
    const rawBase64 = trimmed.slice(ARMOR_PREFIX.length);
    const json = Buffer.from(rawBase64, 'base64url').toString('utf8');
    return JSON.parse(json) as EncryptedEnvelope;
  }

  // Fallback: try raw JSON
  try {
    return JSON.parse(trimmed) as EncryptedEnvelope;
  } catch {
    // Try raw base64url
    try {
      const json = Buffer.from(trimmed, 'base64url').toString('utf8');
      return JSON.parse(json) as EncryptedEnvelope;
    } catch {
      throw new Error('Invalid carry payload format: must be carry:// string or valid JSON');
    }
  }
}
