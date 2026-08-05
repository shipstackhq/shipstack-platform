#!/usr/bin/env node
// Reads jest's --json output (written by test:e2e to e2e/.last-run.json)
// and regenerates e2e/status.md — a plain-text snapshot of the last e2e
// run's pass/fail status per test, grouped by file. Run automatically as
// part of `npm run test:e2e` (see package.json's posttest:e2e script) so
// status.md always reflects the most recent run without a separate step.
const fs = require('fs');
const path = require('path');

const resultsPath = path.join(__dirname, '..', '.last-run.json');
const statusPath = path.join(__dirname, '..', 'status.md');

if (!fs.existsSync(resultsPath)) {
  console.error(`write-status: ${resultsPath} not found — nothing to summarize.`);
  process.exit(0);
}

const data = JSON.parse(fs.readFileSync(resultsPath, 'utf8'));

function relFile(absPath) {
  return path.relative(path.join(__dirname, '..'), absPath);
}

const lines = [];
lines.push('# Auth E2E Status');
lines.push('');
lines.push(`Last run: ${new Date(data.startTime).toISOString()}`);
lines.push(`Result: ${data.success ? '✅ PASSING' : '❌ FAILING'}`);
lines.push(`Tests: ${data.numPassedTests} passed, ${data.numFailedTests} failed, ${data.numTotalTests} total`);
lines.push(`Suites: ${data.numPassedTestSuites} passed, ${data.numFailedTestSuites} failed, ${data.numTotalTestSuites} total`);
lines.push('');

for (const suite of data.testResults) {
  const suiteStatus = suite.status === 'passed' ? '✅ PASS' : '❌ FAIL';
  lines.push(`## ${suiteStatus} — ${relFile(suite.name)}`);
  lines.push('');

  // Group assertions by describe-block (ancestorTitles) for readability —
  // mirrors how the console reporter nests them.
  const byGroup = new Map();
  for (const t of suite.assertionResults) {
    const group = t.ancestorTitles.join(' > ') || '(top level)';
    if (!byGroup.has(group)) byGroup.set(group, []);
    byGroup.get(group).push(t);
  }

  for (const [group, tests] of byGroup) {
    lines.push(`**${group}**`);
    for (const t of tests) {
      const mark = t.status === 'passed' ? '✅' : t.status === 'pending' ? '⏭️' : '❌';
      lines.push(`- ${mark} ${t.title} (${t.duration ?? '?'}ms)`);
      if (t.status === 'failed' && t.failureMessages?.length) {
        const firstLine = t.failureMessages[0].split('\n')[0];
        lines.push(`  - ${firstLine}`);
      }
    }
    lines.push('');
  }
}

fs.writeFileSync(statusPath, lines.join('\n'));
console.log(`write-status: wrote ${relFile(statusPath)}`);
