export const DEMO_INTEREST_OPTIONS = {
  siem: 'AI-Native Wazuh SIEM',
  compliance: 'ComplyHub (ISO/PCI/SOC 2)',
  full: 'All Platform Capabilities',
  training: 'Consultancy & Training',
} as const;

export type DemoInterest = keyof typeof DEMO_INTEREST_OPTIONS;

export interface DemoFormPayload {
  name: string;
  email: string;
  company: string;
  interest: DemoInterest;
}

const NAME_RE = /^[\p{L}\p{M}][\p{L}\p{M}\s'.-]{1,79}$/u;
const EMAIL_RE =
  /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;
const COMPANY_RE = /^[\p{L}\p{N}\s&.,'()\-/]{2,120}$/u;
const BLOCKED_PATTERNS = [
  /<script/i,
  /javascript:/i,
  /on\w+\s*=/i,
  /data:/i,
  /vbscript:/i,
];

const RATE_LIMIT_MS = 60_000;
const RATE_LIMIT_KEY = 'smp-demo-last-submit';

export function sanitizeText(value: string, maxLen: number): string {
  return value
    .replace(/\0/g, '')
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '')
    .replace(/<[^>]*>/g, '')
    .trim()
    .slice(0, maxLen);
}

function containsBlockedContent(value: string): boolean {
  return BLOCKED_PATTERNS.some((pattern) => pattern.test(value));
}

export function validateDemoForm(input: {
  name: string;
  email: string;
  company: string;
  interest: string;
  honeypot: string;
}): { ok: true; data: DemoFormPayload } | { ok: false; error: string } {
  if (input.honeypot.trim().length > 0) {
    return { ok: false, error: 'Submission blocked. Please try again.' };
  }

  const name = sanitizeText(input.name, 80);
  const email = sanitizeText(input.email, 254).toLowerCase();
  const company = sanitizeText(input.company, 120);
  const interest = input.interest.trim() as DemoInterest;

  if (!name || name.length < 2) {
    return { ok: false, error: 'Please enter your full name (at least 2 characters).' };
  }
  if (!NAME_RE.test(name)) {
    return { ok: false, error: 'Name contains invalid characters.' };
  }

  if (!email || !EMAIL_RE.test(email)) {
    return { ok: false, error: 'Please enter a valid work email address.' };
  }
  if (email.length > 254) {
    return { ok: false, error: 'Email address is too long.' };
  }

  if (!company || company.length < 2) {
    return { ok: false, error: 'Please enter your company name.' };
  }
  if (!COMPANY_RE.test(company)) {
    return { ok: false, error: 'Company name contains invalid characters.' };
  }

  if (!(interest in DEMO_INTEREST_OPTIONS)) {
    return { ok: false, error: 'Please select a valid primary focus.' };
  }

  const combined = `${name}${email}${company}`;
  if (containsBlockedContent(combined)) {
    return { ok: false, error: 'Submission contains unsupported content.' };
  }

  return {
    ok: true,
    data: { name, email, company, interest },
  };
}

export function checkRateLimit(): { ok: true } | { ok: false; error: string } {
  try {
    const last = Number(sessionStorage.getItem(RATE_LIMIT_KEY) || '0');
    const elapsed = Date.now() - last;
    if (last > 0 && elapsed < RATE_LIMIT_MS) {
      const seconds = Math.ceil((RATE_LIMIT_MS - elapsed) / 1000);
      return {
        ok: false,
        error: `Please wait ${seconds} seconds before submitting again.`,
      };
    }
  } catch {
    // sessionStorage unavailable — allow submit
  }
  return { ok: true };
}

export function markSubmitted(): void {
  try {
    sessionStorage.setItem(RATE_LIMIT_KEY, String(Date.now()));
  } catch {
    // ignore
  }
}

export async function submitDemoToFormSubmit(
  recipientEmail: string,
  payload: DemoFormPayload,
  signal?: AbortSignal,
): Promise<{ ok: true } | { ok: false; error: string }> {
  if (!recipientEmail || !EMAIL_RE.test(recipientEmail)) {
    return { ok: false, error: 'Demo form is not configured. Contact support directly.' };
  }

  const interestLabel = DEMO_INTEREST_OPTIONS[payload.interest];

  const response = await fetch(`https://formsubmit.co/ajax/${encodeURIComponent(recipientEmail)}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: JSON.stringify({
      name: payload.name,
      email: payload.email,
      company: payload.company,
      interest: interestLabel,
      _subject: `SecurityMind Pro — Demo Request from ${payload.name}`,
      _template: 'table',
      _captcha: 'false',
      _honey: '',
    }),
    signal,
  });

  let result: { success?: string; message?: string } | null = null;
  try {
    result = await response.json();
  } catch {
    return { ok: false, error: 'Unexpected server response. Please try again.' };
  }

  if (!response.ok || !result?.success) {
    return {
      ok: false,
      error: result?.message || 'Could not send your request. Please try again later.',
    };
  }

  return { ok: true };
}
