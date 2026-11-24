// Secret patterns of data.secret-in-asset (06, chapter 4.8); redaction uses all of them (07-REQ-13).
import type { Confidence } from '../types/index.ts';

export interface SecretPattern {
  /** Discriminator of the finding (07-REQ-06), e.g. 'aws-access-key'. */
  name: string;
  title: string;
  /** Global regex; the whole match is the secret. */
  regex: RegExp;
  confidence: Confidence;
  /** Off in the recommended preset (too many false positives). */
  offByDefault?: boolean;
}

export const SECRET_PATTERNS: readonly SecretPattern[] = [
  {
    name: 'aws-access-key',
    title: 'AWS access key',
    regex: /\bAKIA[0-9A-Z]{16}\b/g,
    confidence: 'high',
  },
  {
    name: 'aws-secret-key',
    title: 'AWS secret access key',
    regex: /aws(?:.{0,20})?(?:secret|private).{0,20}['"][0-9a-zA-Z/+]{40}['"]/gi,
    confidence: 'high',
  },
  {
    name: 'github-token',
    title: 'GitHub token',
    regex: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g,
    confidence: 'high',
  },
  {
    name: 'stripe-secret-key',
    title: 'Stripe secret key',
    regex: /\bsk_live_[0-9a-zA-Z]{24,}\b/g,
    confidence: 'high',
  },
  {
    name: 'slack-token',
    title: 'Slack token',
    regex: /\bxox[baprs]-[0-9A-Za-z-]{10,}/g,
    confidence: 'high',
  },
  {
    name: 'private-key',
    title: 'Private key',
    regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----/g,
    confidence: 'high',
  },
  // Maps and Firebase keys are public by design (06, chapter 4.8).
  {
    name: 'google-api-key',
    title: 'Google API key',
    regex: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    confidence: 'low',
  },
  {
    name: 'generic-secret',
    title: 'Generic secret assignment',
    regex: /\b(?:secret|client_secret|api_secret)["']?\s*[:=]\s*["'][^"'\s]{8,}["']/gi,
    confidence: 'low',
    offByDefault: true,
  },
];
