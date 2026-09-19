export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface SecretFinding {
  key: string;
  maskedValue: string;
  rawValue: string;
  service: string;
  type: string;
  severity: Severity;
  rotationUrl: string;
  dangerNotes: string;
  rotationGuide: string;
}

interface PatternRule {
  service: string;
  type: string;
  severity: Severity;
  rotationUrl: string;
  dangerNotes: string;
  rotationGuide: string;
  test: (key: string, value: string) => boolean;
}

export function maskSecret(value: string): string {
  if (!value) return '';
  if (value.length <= 8) return '****';
  return `${value.slice(0, 4)}...${value.slice(-4)}`;
}

export const KNOWN_RULES: PatternRule[] = [
  // Supabase
  {
    service: 'Supabase',
    type: 'Service Role Key (Admin Bypass)',
    severity: 'CRITICAL',
    rotationUrl: 'https://supabase.com/dashboard/project/_/settings/api',
    dangerNotes: 'Bypasses Row Level Security (RLS). Grants full write/read access to the entire database.',
    rotationGuide: 'Go to Supabase Settings > API > click "Generate new secret" for service_role.',
    test: (k, v) =>
      (k.toUpperCase().includes('SUPABASE') && (k.toUpperCase().includes('SERVICE') || k.toUpperCase().includes('SECRET'))) ||
      (v.startsWith('ey') && v.includes('service_role'))
  },
  {
    service: 'Supabase',
    type: 'Anon Public Key',
    severity: 'LOW',
    rotationUrl: 'https://supabase.com/dashboard/project/_/settings/api',
    dangerNotes: 'Public client key. Controlled by Row Level Security (RLS) policies.',
    rotationGuide: 'Rotate alongside service_role key if project ownership is transferred.',
    test: (k, v) =>
      k.toUpperCase().includes('SUPABASE_ANON_KEY') || (v.startsWith('ey') && v.includes('"role":"anon"'))
  },

  // Stripe
  {
    service: 'Stripe',
    type: 'Live Secret Key',
    severity: 'CRITICAL',
    rotationUrl: 'https://dashboard.stripe.com/apikeys',
    dangerNotes: 'Allows charging customers, initiating refunds, and reading customer/card records.',
    rotationGuide: 'Go to Stripe Dashboard > Developers > API keys > Create restricted key or roll secret key.',
    test: (k, v) => v.startsWith('sk_live_') || (k.toUpperCase().includes('STRIPE_SECRET') && !v.includes('test'))
  },
  {
    service: 'Stripe',
    type: 'Test Secret Key',
    severity: 'LOW',
    rotationUrl: 'https://dashboard.stripe.com/apikeys',
    dangerNotes: 'Test-mode operations only. No real money risk.',
    rotationGuide: 'Roll in test mode dashboard when changing development teams.',
    test: (k, v) => v.startsWith('sk_test_')
  },
  {
    service: 'Stripe',
    type: 'Webhook Signing Secret',
    severity: 'HIGH',
    rotationUrl: 'https://dashboard.stripe.com/webhooks',
    dangerNotes: 'Attacker could spoof billing webhooks and fulfill fake orders/subscriptions.',
    rotationGuide: 'In Stripe Webhooks tab, reveal and roll the webhook signing secret.',
    test: (k, v) => v.startsWith('whsec_') || k.toUpperCase().includes('STRIPE_WEBHOOK')
  },

  // OpenAI
  {
    service: 'OpenAI',
    type: 'API Secret Key',
    severity: 'HIGH',
    rotationUrl: 'https://platform.openai.com/api-keys',
    dangerNotes: 'Attacker can drain OpenAI credit balance and run models under your organization billing.',
    rotationGuide: 'OpenAI Dashboard > API keys > Revoke existing key and create a new project-scoped key.',
    test: (k, v) => v.startsWith('sk-') && !v.startsWith('sk_live_') && !v.startsWith('sk_test_') && !v.startsWith('sk-ant-')
  },

  // Anthropic
  {
    service: 'Anthropic',
    type: 'Claude API Key',
    severity: 'HIGH',
    rotationUrl: 'https://console.anthropic.com/settings/keys',
    dangerNotes: 'Direct access to Claude models billed to your workspace.',
    rotationGuide: 'Anthropic Console > Settings > API Keys > Delete previous key and generate replacement.',
    test: (k, v) => v.startsWith('sk-ant-') || k.toUpperCase().includes('ANTHROPIC_API_KEY')
  },

  // Resend
  {
    service: 'Resend',
    type: 'Email API Key',
    severity: 'HIGH',
    rotationUrl: 'https://resend.com/api-keys',
    dangerNotes: 'Allows sending emails from verified business domains (phishing / brand hijacking).',
    rotationGuide: 'Resend Console > API Keys > Delete old key and create new scoped key.',
    test: (k, v) => v.startsWith('re_') || k.toUpperCase().includes('RESEND_API_KEY')
  },

  // AWS
  {
    service: 'AWS',
    type: 'IAM Access Key ID',
    severity: 'CRITICAL',
    rotationUrl: 'https://console.aws.amazon.com/iam/home#/security_credentials',
    dangerNotes: 'Allows provisioning infrastructure, reading S3 buckets, and incurring massive compute bills.',
    rotationGuide: 'AWS IAM Console > Users > Security Credentials > Deactivate and delete old access key.',
    test: (k, v) => /^AKIA[0-9A-Z]{16}$/.test(v) || /^ASIA[0-9A-Z]{16}$/.test(v)
  },

  // GitHub
  {
    service: 'GitHub',
    type: 'Personal Access Token',
    severity: 'CRITICAL',
    rotationUrl: 'https://github.com/settings/tokens',
    dangerNotes: 'Grants access to private repositories, code pushes, and organization packages.',
    rotationGuide: 'GitHub > Settings > Developer settings > Personal access tokens > Revoke token.',
    test: (k, v) => v.startsWith('ghp_') || v.startsWith('github_pat_') || v.startsWith('gho_')
  },

  // Google / Firebase
  {
    service: 'Google / Firebase',
    type: 'API Key',
    severity: 'MEDIUM',
    rotationUrl: 'https://console.cloud.google.com/apis/credentials',
    dangerNotes: 'May allow consuming GCP APIs or querying Firebase instances without restrictions.',
    rotationGuide: 'Google Cloud Console > APIs & Services > Credentials > Regenerate API key.',
    test: (k, v) => v.startsWith('AIza') && v.length === 39
  },

  // SendGrid
  {
    service: 'SendGrid',
    type: 'Mail API Key',
    severity: 'HIGH',
    rotationUrl: 'https://app.sendgrid.com/settings/api_keys',
    dangerNotes: 'Enables outbound email sending through authenticated domains.',
    rotationGuide: 'Sendgrid Settings > API Keys > Delete key and generate restricted replacement.',
    test: (k, v) => v.startsWith('SG.')
  },

  // Twilio
  {
    service: 'Twilio',
    type: 'Account SID or Auth Token',
    severity: 'HIGH',
    rotationUrl: 'https://console.twilio.com',
    dangerNotes: 'Can send SMS, make voice calls, and trigger toll fraud at high cost.',
    rotationGuide: 'Twilio Console > Account > API keys & tokens > Regenerate Auth Token.',
    test: (k, v) => (k.toUpperCase().includes('TWILIO') && v.startsWith('AC')) || k.toUpperCase().includes('TWILIO_AUTH_TOKEN')
  },

  // PostHog
  {
    service: 'PostHog',
    type: 'Personal API Key / Secret',
    severity: 'MEDIUM',
    rotationUrl: 'https://app.posthog.com/me/settings',
    dangerNotes: 'Can read analytics data, user events, and cohort demographics.',
    rotationGuide: 'PostHog > Account Settings > Personal API Keys > Create new key and revoke old one.',
    test: (k, v) => v.startsWith('phs_') || (k.toUpperCase().includes('POSTHOG') && k.toUpperCase().includes('SECRET'))
  },

  // Paystack
  {
    service: 'Paystack',
    type: 'Secret Key',
    severity: 'CRITICAL',
    rotationUrl: 'https://dashboard.paystack.com/#/settings/developer',
    dangerNotes: 'Allows initiating refunds, managing transfers, and accessing transaction data.',
    rotationGuide: 'Paystack Dashboard > Settings > API Keys & Webhooks > Generate new secret key.',
    test: (k, v) => (v.startsWith('sk_live_') && k.toUpperCase().includes('PAYSTACK')) || k.toUpperCase().includes('PAYSTACK_SECRET')
  },

  // Monnify
  {
    service: 'Monnify',
    type: 'API Secret Key',
    severity: 'CRITICAL',
    rotationUrl: 'https://app.monnify.com/developer/api-keys',
    dangerNotes: 'Financial transfer operations and payment verification bypass.',
    rotationGuide: 'Monnify Portal > Developer > API Keys > Roll Secret Key.',
    test: (k) => k.toUpperCase().includes('MONNIFY_SECRET') || k.toUpperCase().includes('MONNIFY_API_KEY')
  },

  // Database URLs (Postgres, MongoDB, Redis, MySQL)
  {
    service: 'Database',
    type: 'Connection String / Credentials',
    severity: 'CRITICAL',
    rotationUrl: 'Your Database Hosting Dashboard (Neon, Supabase, Railway, MongoDB Atlas)',
    dangerNotes: 'Direct, unmetered access to query, dump, modify, or drop the entire application database.',
    rotationGuide: 'Reset user password or rotate connection pool string in database host.',
    test: (k, v) =>
      /^(postgres|postgresql|mongodb|mysql|redis):\/\//i.test(v) ||
      k.toUpperCase().includes('DATABASE_URL') ||
      k.toUpperCase().includes('POSTGRES_URL') ||
      k.toUpperCase().includes('MONGODB_URI')
  },

  // JWT / NextAuth / Session Secret
  {
    service: 'Session & Auth',
    type: 'Application Secret (JWT / NextAuth)',
    severity: 'HIGH',
    rotationUrl: 'Locally generated (use `openssl rand -base64 32`)',
    dangerNotes: 'Previous maintainers could forge valid session cookies to impersonate any user or admin.',
    rotationGuide: 'Generate a new 32-byte random string using: openssl rand -base64 32 and update immediately.',
    test: (k) =>
      k.toUpperCase().includes('NEXTAUTH_SECRET') ||
      k.toUpperCase().includes('JWT_SECRET') ||
      k.toUpperCase().includes('AUTH_SECRET') ||
      k.toUpperCase().includes('SESSION_SECRET')
  }
];

/**
 * Audit all environment variables and return detected secrets with actionable takeover rotation advice.
 */
export function auditEnvMap(map: Record<string, string>): SecretFinding[] {
  const findings: SecretFinding[] = [];

  for (const [key, value] of Object.entries(map)) {
    if (!value || value.trim() === '') continue;

    let matched = false;
    for (const rule of KNOWN_RULES) {
      if (rule.test(key, value)) {
        findings.push({
          key,
          maskedValue: maskSecret(value),
          rawValue: value,
          service: rule.service,
          type: rule.type,
          severity: rule.severity,
          rotationUrl: rule.rotationUrl,
          dangerNotes: rule.dangerNotes,
          rotationGuide: rule.rotationGuide
        });
        matched = true;
        break; // Match first specific rule
      }
    }

    // Generic heuristic for high-entropy secret-looking keys not matched above
    if (!matched) {
      const upperKey = key.toUpperCase();
      if (
        (upperKey.includes('SECRET') || upperKey.includes('TOKEN') || upperKey.includes('PRIVATE_KEY')) &&
        value.length >= 16
      ) {
        findings.push({
          key,
          maskedValue: maskSecret(value),
          rawValue: value,
          service: 'Custom / Unclassified',
          type: 'Sensitive Secret / Token',
          severity: 'HIGH',
          rotationUrl: 'Service provider dashboard',
          dangerNotes: 'Detected high-entropy secret name and value. Confirm origin and rotate upon takeover.',
          rotationGuide: 'Identify provider and generate fresh credentials.'
        });
      }
    }
  }

  // Sort by severity (CRITICAL > HIGH > MEDIUM > LOW > INFO)
  const order: Record<Severity, number> = {
    CRITICAL: 1,
    HIGH: 2,
    MEDIUM: 3,
    LOW: 4,
    INFO: 5
  };

  return findings.sort((a, b) => order[a.severity] - order[b.severity]);
}
