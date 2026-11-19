// Deterministic rules. No model output is trusted here: every decision is
// computed from what CloudFormation says about the stack right now.

const TTL = /^([1-9]\d{0,3})([mhd])$/;
const UNIT_MS = { m: 60_000, h: 3_600_000, d: 86_400_000 };

export const MAX_SNOOZE_HOURS = 24;
export const MAX_DELETES_PER_HOUR = 3;
export const APPROVAL_TTL_SECONDS = 300;

export function parseTtl(value) {
  const m = TTL.exec(String(value ?? '').trim());
  return m ? Number(m[1]) * UNIT_MS[m[2]] : null;
}

export function tagsOf(stack) {
  return Object.fromEntries((stack.Tags ?? []).map((t) => [t.Key, t.Value]));
}

// Returns { eligible, reasons[], expiresAt } for one stack.
// `snoozeHours` is the extra time a human or the agent has already granted.
export function evaluate(stack, { now, tagKey = 'cleanup-after', selfStackId, snoozeHours = 0 }) {
  const tags = tagsOf(stack);
  const reasons = [];
  let expiresAt = null;

  if (stack.StackId === selfStackId) reasons.push('SELF');
  if (stack.ParentId || (stack.RootId && stack.RootId !== stack.StackId)) reasons.push('NESTED_STACK');
  if (String(tags.env ?? '').toLowerCase() === 'prod') reasons.push('PRODUCTION');
  if (stack.EnableTerminationProtection) reasons.push('TERMINATION_PROTECTED');
  if (/_IN_PROGRESS$/.test(stack.StackStatus ?? '')) reasons.push('OPERATION_IN_PROGRESS');

  if (!(tagKey in tags)) {
    reasons.push('NO_TTL_TAG');
  } else {
    const ttlMs = parseTtl(tags[tagKey]);
    if (ttlMs === null) {
      reasons.push('INVALID_TTL');
    } else {
      const base = new Date(stack.LastUpdatedTime ?? stack.CreationTime).getTime();
      expiresAt = new Date(base + ttlMs + snoozeHours * UNIT_MS.h);
      if (expiresAt.getTime() > now.getTime()) reasons.push('NOT_EXPIRED');
    }
  }
  return { eligible: reasons.length === 0, reasons, expiresAt: expiresAt?.toISOString() ?? null };
}

export function validSnooze(hours) {
  return Number.isInteger(hours) && hours >= 1 && hours <= MAX_SNOOZE_HOURS;
}
