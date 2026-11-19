#!/usr/bin/env node
// Chat with the Sandbox Janitor. You are both the requester and the approver:
// when the agent asks to delete a stack, you see the stack's facts from AWS
// and type y or n.
//   node bin/janitor.mjs                 interactive
//   node bin/janitor.mjs "one question"  single turn
import readline from 'node:readline';
import { outputs } from '../lib/config.mjs';
import { Session, shortName } from '../lib/agent.mjs';
import { recordApproval, stackFacts } from '../lib/approvals.mjs';

const o = await outputs();
const rl = readline.createInterface({ input: process.stdin });
// A small line queue, so the client also works when input is piped in.
const lines = [];
const waiters = [];
let closed = false;
rl.on('line', (l) => (waiters.length ? waiters.shift()(l) : lines.push(l)));
rl.on('close', () => {
  closed = true;
  for (const w of waiters) w(null);
});
async function question(prompt) {
  process.stdout.write(prompt);
  const line = lines.length ? lines.shift() : closed ? null : await new Promise((r) => waiters.push(r));
  if (!process.stdin.isTTY) process.stdout.write(`${line ?? ''}\n`);
  return line ?? '';
}
const dim = (s) => `\x1b[2m${s}\x1b[0m`;
const bold = (s) => `\x1b[1m${s}\x1b[0m`;

async function approver({ stackName, reason }) {
  const facts = await stackFacts(stackName);
  console.log(`\n${bold('APPROVAL REQUEST')}  The agent wants to delete one stack.`);
  if (!facts) {
    console.log(`  No stack named "${stackName}" exists. Denied.`);
    return { approved: false, note: 'stack not found' };
  }
  console.log(`  Stack      ${facts.stackName}`);
  console.log(`  Status     ${facts.status}   created ${facts.created}`);
  console.log(`  Tags       ${JSON.stringify(facts.tags)}`);
  console.log(`  Protected  ${facts.terminationProtection}`);
  console.log(dim(`  Agent's reason (unverified): ${reason}`));
  const answer = (await question('  Approve deleting this stack? [y/N] ')).trim().toLowerCase();
  if (answer !== 'y') return { approved: false, note: 'operator declined' };
  await recordApproval(o.ApprovalsTable, facts.stackId, process.env.USER ?? process.env.USERNAME ?? 'operator');
  return { approved: true, note: 'valid for 5 minutes, for this stack only' };
}

const session = new Session({ harnessArn: o.HarnessArn, approver });

async function ask(text) {
  const turn = await session.send(text);
  for (const c of turn.toolCalls) {
    const r = c.result ?? {};
    const verdict = r.ok === false ? `refused by ${r.refusedBy}: ${(r.reasons ?? []).join(', ')}` : c.status === 'error' ? 'denied before the tool ran' : 'ok';
    console.log(dim(`  [tool] ${shortName(c.name)} ${JSON.stringify(c.input)} -> ${verdict}`));
  }
  if (turn.stopReasons.includes('guardrail_intervened')) console.log(dim('  [guardrail intervened]'));
  for (const e of turn.errors) console.log(dim(`  [error] ${e}`));
  console.log(`\n${turn.text.replace(/<thinking>[\s\S]*?<\/thinking>\s*/g, '').trim()}\n`);
}

if (process.argv[2]) {
  await ask(process.argv.slice(2).join(' '));
} else {
  console.log(bold('Sandbox Janitor') + dim('  (empty line to quit)'));
  for (;;) {
    const line = (await question('> ')).trim();
    if (!line) break;
    await ask(line);
  }
}
rl.close();
