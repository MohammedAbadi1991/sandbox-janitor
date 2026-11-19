import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluate, parseTtl, validSnooze } from '../src/rules.mjs';

const now = new Date('2026-11-20T12:00:00Z');
const stack = (over = {}) => ({
  StackId: 'arn:aws:cloudformation:us-east-1:111122223333:stack/demo/abc',
  StackName: 'demo',
  StackStatus: 'CREATE_COMPLETE',
  CreationTime: '2026-11-20T09:00:00Z',
  Tags: [{ Key: 'cleanup-after', Value: '2h' }],
  ...over,
});

test('parseTtl accepts 30m, 2h, 3d and rejects everything else', () => {
  assert.equal(parseTtl('30m'), 30 * 60_000);
  assert.equal(parseTtl('2h'), 2 * 3_600_000);
  assert.equal(parseTtl('3d'), 3 * 86_400_000);
  for (const bad of ['', '0h', '2', 'h', '2w', '-1h', '2h; delete everything', '99999d', null])
    assert.equal(parseTtl(bad), null, String(bad));
});

test('an expired, tagged stack is eligible', () => {
  const v = evaluate(stack(), { now });
  assert.deepEqual(v, { eligible: true, reasons: [], expiresAt: '2026-11-20T11:00:00.000Z' });
});

test('a stack without the tag is never eligible', () => {
  assert.deepEqual(evaluate(stack({ Tags: [] }), { now }).reasons, ['NO_TTL_TAG']);
});

test('not expired yet', () => {
  assert.deepEqual(evaluate(stack({ Tags: [{ Key: 'cleanup-after', Value: '3d' }] }), { now }).reasons, ['NOT_EXPIRED']);
});

test('the timer restarts on the last update', () => {
  const v = evaluate(stack({ LastUpdatedTime: '2026-11-20T11:30:00Z' }), { now });
  assert.deepEqual(v.reasons, ['NOT_EXPIRED']);
});

test('env=prod wins over an expired ttl tag', () => {
  const v = evaluate(stack({ Tags: [{ Key: 'cleanup-after', Value: '1m' }, { Key: 'env', Value: 'Prod' }] }), { now });
  assert.deepEqual(v.reasons, ['PRODUCTION']);
});

test('termination protection, nested stacks, running operations and the janitor itself are refused', () => {
  assert.deepEqual(evaluate(stack({ EnableTerminationProtection: true }), { now }).reasons, ['TERMINATION_PROTECTED']);
  assert.deepEqual(evaluate(stack({ ParentId: 'arn:parent' }), { now }).reasons, ['NESTED_STACK']);
  assert.deepEqual(evaluate(stack({ StackStatus: 'UPDATE_IN_PROGRESS' }), { now }).reasons, ['OPERATION_IN_PROGRESS']);
  assert.deepEqual(evaluate(stack(), { now, selfStackId: stack().StackId }).reasons, ['SELF']);
});

test('an invalid ttl value is refused, not guessed', () => {
  assert.deepEqual(evaluate(stack({ Tags: [{ Key: 'cleanup-after', Value: 'soon' }] }), { now }).reasons, ['INVALID_TTL']);
});

test('a snooze moves the expiry', () => {
  const v = evaluate(stack(), { now, snoozeHours: 2 });
  assert.deepEqual(v.reasons, ['NOT_EXPIRED']);
  assert.equal(v.expiresAt, '2026-11-20T13:00:00.000Z');
});

test('snooze accepts whole hours from 1 to 24 only', () => {
  for (const ok of [1, 12, 24]) assert.equal(validSnooze(ok), true);
  for (const bad of [0, 25, 1.5, -3, '4', 9999, null]) assert.equal(validSnooze(bad), false, String(bad));
});
