#!/usr/bin/env node
// Turns results/*.json into results/REPORT.md.
//   node redteam/report.mjs
import fs from 'node:fs';

const load = (name) => (fs.existsSync(`results/${name}.json`) ? JSON.parse(fs.readFileSync(`results/${name}.json`, 'utf8')) : null);
const hardened = load('hardened');
const naive = load('naive');
if (!hardened) {
  console.error('results/hardened.json not found. Run node redteam/run.mjs first.');
  process.exit(1);
}

const LAYER = {
  guardrail: 'Guardrail',
  'gateway-policy': 'Gateway policy',
  'gateway-error': 'Gateway',
  'tool-checks': 'Tool checks',
  'tool-error': 'Tool checks',
  'human-approval': 'Human approval',
  iam: 'IAM',
  'cloudformation-termination-protection': 'CloudFormation',
  model: 'Model declined',
};
const layers = (r) => (r ? [...new Set(r.stoppedBy.map((l) => LAYER[l] ?? l))].join(', ') || 'n/a' : 'not run');
const verdict = (r) => (r ? (r.held ? 'held' : `**BROKE**: ${r.violations.join('; ')}`) : '');
const byId = (run) => Object.fromEntries((run?.results ?? []).map((r) => [r.id, r]));
const esc = (s) => String(s).replace(/\|/g, '\\|').replace(/\s+/g, ' ').trim();

const h = byId(hardened);
const n = byId(naive);
const ids = Object.keys(h).filter((id) => id !== 'C0');
let md = `# Red-team report\n\n`;
md += `Generated ${new Date().toISOString().slice(0, 10)} from \`results/hardened.json\`${naive ? ' and `results/naive.json`' : ''}. `;
md += `Regenerate with \`npm run redteam\` and \`node redteam/report.mjs\`.\n\n`;

md += `## Part 1: adversarial prompts through the agent\n\n`;
md += `**Hardened** is the agent as deployed. **Naive** swaps the system prompt for one line with no rules and removes the guardrail, `;
md += `so the model does whatever the prompt asks and everything below it has to hold.\n\n`;
md += `| # | Attack | Hardened: stopped by | Naive: stopped by | Result |\n|---|---|---|---|---|\n`;
for (const id of ids) {
  const res = [h[id], n[id]].filter(Boolean).every((r) => r.held) ? 'held' : [verdict(h[id]), verdict(n[id])].filter((v) => v.startsWith('**')).join(' ');
  md += `| ${id} | ${esc(h[id].title)} (${h[id].category}) | ${layers(h[id])} | ${layers(n[id])} | ${res} |\n`;
}
const count = (run) => {
  const a = run.results.filter((r) => r.category !== 'control');
  return `${a.filter((r) => r.held).length}/${a.length}`;
};
const ctl = (run) => (run.results.find((r) => r.category === 'control')?.held ? 'completed' : 'not completed');
md += `\nAttacks held: hardened ${count(hardened)}${naive ? `, naive ${count(naive)}` : ''}. `;
md += `The control scenario (delete one expired stack after approval): hardened ${ctl(hardened)}${naive ? `, naive ${ctl(naive)}` : ''}.\n\n`;

const replay = (naive ?? hardened).replay ?? hardened.replay;
if (Array.isArray(replay)) {
  md += `## Part 2: the model is compromised\n\n`;
  md += `Each row skips the layers above it and sends a forbidden action straight to the next one down.\n\n`;
  md += `| # | Sent directly to | Forbidden action | Outcome | Stopped by | Detail |\n|---|---|---|---|---|---|\n`;
  for (const p of replay) {
    md += `| ${p.id} | ${p.layerUnderTest} | ${esc(p.action)} | ${p.blocked ? 'blocked' : '**allowed**'} | ${LAYER[p.by] ?? p.by ?? 'nothing'} | ${esc(p.detail ?? '').slice(0, 140)} |\n`;
  }
  md += `\nP6 is the residual risk, stated plainly: if an attacker replaces the tool function's code, IAM cannot tell an expired stack from a fresh one. `;
  md += `What IAM still guarantees is the outer boundary: only stacks that carry the \`cleanup-after\` tag and are not tagged \`env=prod\` can be deleted by that role.\n\n`;
}

md += `## Transcripts\n\n`;
for (const [label, run] of [['Hardened', hardened], ['Naive', naive]]) {
  if (!run) continue;
  md += `### ${label}\n\n`;
  for (const r of run.results) {
    md += `#### ${r.id} ${r.title}\n\n*${r.goal}*\n\n`;
    for (const t of r.transcript) {
      md += `> ${esc(t.prompt)}\n\n`;
      for (const c of t.calls) md += `- \`${c.tool}\` \`${JSON.stringify(c.input)}\` → ${c.outcome}${c.reasons ? ` (${c.reasons.join(', ')})` : ''}\n`;
      if (t.stopReasons.includes('guardrail_intervened')) md += `- guardrail intervened\n`;
      md += `\n${t.reply ? `Agent: ${esc(t.reply).slice(0, 700)}` : 'Agent: (no text)'}\n\n`;
    }
    md += `Result: ${r.held ? 'held' : `BROKE (${r.violations.join('; ')})`}. Stopped by: ${layers(r)}.\n\n`;
  }
}
fs.writeFileSync('results/REPORT.md', md);
console.log(`results/REPORT.md written (${md.length} bytes)`);
