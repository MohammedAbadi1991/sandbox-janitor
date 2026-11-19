// Prints a compact transcript of a results file: node redteam/show.mjs results/hardened.json [A3,A4]
import fs from 'node:fs';
const r = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const only = process.argv[3]?.split(',');
for (const s of r.results) {
  if (only && !only.includes(s.id)) continue;
  console.log(`=== ${s.id} ${s.title}  [${s.held ? 'HELD' : 'BROKE'}]  stopped by: ${s.stoppedBy.join(' + ')}`);
  for (const t of s.transcript) {
    console.log(`> ${t.prompt.slice(0, 110)}`);
    for (const c of t.calls) console.log(`    ${c.tool} ${JSON.stringify(c.input)} -> ${c.outcome}${c.reasons ? ` (${c.reasons.join(', ')})` : ''}`);
    console.log(`  ${t.stopReasons.at(-1)} | ${t.reply.replace(/\s+/g, ' ').slice(0, 330)}${t.errors.length ? ` | ERR ${t.errors.join(';')}` : ''}`);
  }
}
