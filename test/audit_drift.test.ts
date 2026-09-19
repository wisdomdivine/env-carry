import { describe, it, expect } from 'vitest';
import { auditEnvMap } from '../src/audit/detector.js';
import { checkDrift, isPlaceholder } from '../src/drift.js';

describe('audit detector', () => {
  it('detects Supabase service role key and flags it as CRITICAL', () => {
    const findings = auditEnvMap({
      SUPABASE_SERVICE_ROLE_KEY: 'eyJh...service_role...secret',
      SUPABASE_ANON_KEY: 'eyJh..."role":"anon"...public'
    });

    expect(findings.length).toBe(2);
    const critical = findings.find((f) => f.severity === 'CRITICAL');
    expect(critical).toBeDefined();
    expect(critical?.service).toBe('Supabase');
    expect(critical?.dangerNotes).toContain('Bypasses Row Level Security');
  });

  it('detects Stripe live secret key as CRITICAL and test key as LOW', () => {
    const findings = auditEnvMap({
      STRIPE_LIVE_KEY: 'sk_live_51ABCDEFGHIJKLM1234567890',
      STRIPE_TEST_KEY: 'sk_test_51XYZ'
    });

    expect(findings.length).toBe(2);
    const live = findings.find((f) => f.key === 'STRIPE_LIVE_KEY');
    const test = findings.find((f) => f.key === 'STRIPE_TEST_KEY');
    expect(live?.severity).toBe('CRITICAL');
    expect(test?.severity).toBe('LOW');
  });

  it('detects OpenAI and Resend keys', () => {
    const findings = auditEnvMap({
      OPENAI_API_KEY: 'sk-proj-1234567890abcdef',
      RESEND_API_KEY: 're_123456789_abcdef'
    });

    expect(findings).toHaveLength(2);
    expect(findings.map((f) => f.service)).toEqual(
      expect.arrayContaining(['OpenAI', 'Resend'])
    );
  });
});

describe('drift detector', () => {
  it('identifies placeholder values', () => {
    expect(isPlaceholder('your_api_key_here')).toBe(true);
    expect(isPlaceholder('TODO')).toBe(true);
    expect(isPlaceholder('xxx')).toBe(true);
    expect(isPlaceholder('<enter-secret>')).toBe(true);
    expect(isPlaceholder('real_production_secret_key_123')).toBe(false);
  });

  it('flags missing keys, unconfigured placeholders, and extra keys', () => {
    const active = `
DATABASE_URL=postgres://user:pass@localhost:5432/db
API_KEY=your_key_here
NEW_INTERNAL_KEY=123
EMPTY_KEY=
`;
    const example = `
DATABASE_URL=
API_KEY=
REDIS_URL=
EMPTY_KEY=
`;
    const report = checkDrift(active, example);

    expect(report.missingKeys).toContain('REDIS_URL');
    expect(report.extraKeys).toContain('NEW_INTERNAL_KEY');
    expect(report.emptyKeys).toContain('EMPTY_KEY');
    expect(report.placeholderKeys).toEqual([
      { key: 'API_KEY', value: 'your_key_here' }
    ]);
    expect(report.isHealthy).toBe(false);
  });
});
