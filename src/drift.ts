import fs from 'node:fs';
import path from 'node:path';
import { parseEnv } from './parser.js';

export interface DriftReport {
  examplePath: string;
  envPath: string;
  missingKeys: string[];
  extraKeys: string[];
  emptyKeys: string[];
  placeholderKeys: Array<{ key: string; value: string }>;
  isHealthy: boolean;
}

const PLACEHOLDER_PATTERNS = [
  /^(your[_-]|enter[_-]|insert[_-]|replace[_-]|my[_-])/i,
  /\b(todo|change[_-]?me|dummy|placeholder|your_key_here)\b/i,
  /^xxx+$/i,
  /^<.*>$/,
  /^\[.*\]$/,
  /^\.\.\.$/
];

/**
 * Checks if a value appears to be an unconfigured placeholder.
 */
export function isPlaceholder(val: string): boolean {
  const trimmed = val.trim();
  if (!trimmed) return false;
  return PLACEHOLDER_PATTERNS.some((pattern) => pattern.test(trimmed));
}

/**
 * Finds candidate example env files in the given directory.
 */
export function findExampleEnvFile(dir: string = process.cwd()): string | null {
  const candidates = [
    '.env.example',
    '.env.template',
    '.env.sample',
    '.env.dist',
    'env.example'
  ];

  for (const candidate of candidates) {
    const fullPath = path.resolve(dir, candidate);
    if (fs.existsSync(fullPath)) {
      return fullPath;
    }
  }
  return null;
}

/**
 * Compares an active .env against an example/template env.
 */
export function checkDrift(
  activeEnvContent: string,
  exampleEnvContent: string,
  activePath: string = '.env',
  examplePath: string = '.env.example'
): DriftReport {
  const activeParsed = parseEnv(activeEnvContent);
  const exampleParsed = parseEnv(exampleEnvContent);

  const activeKeys = new Set(Object.keys(activeParsed.map));
  const exampleKeys = new Set(Object.keys(exampleParsed.map));

  const missingKeys: string[] = [];
  const extraKeys: string[] = [];
  const emptyKeys: string[] = [];
  const placeholderKeys: Array<{ key: string; value: string }> = [];

  for (const key of exampleKeys) {
    if (!activeKeys.has(key)) {
      missingKeys.push(key);
    }
  }

  for (const [key, value] of Object.entries(activeParsed.map)) {
    if (!exampleKeys.has(key)) {
      extraKeys.push(key);
    }

    if (!value || value.trim() === '') {
      emptyKeys.push(key);
    } else if (isPlaceholder(value)) {
      placeholderKeys.push({ key, value });
    }
  }

  const isHealthy =
    missingKeys.length === 0 &&
    emptyKeys.length === 0 &&
    placeholderKeys.length === 0;

  return {
    examplePath,
    envPath: activePath,
    missingKeys,
    extraKeys,
    emptyKeys,
    placeholderKeys,
    isHealthy
  };
}
