const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

// Test running jocky.exe run directly
console.log('Testing jocky.exe run basic_system_triage.jy...');
const start = Date.now();
try {
  const out = execSync('.\\target\\release\\jocky.exe run examples/basic_system_triage.jy --output build/test_run', { encoding: 'utf8' });
  console.log('Success in', Date.now() - start, 'ms');
  console.log(out);
} catch (e) {
  console.error('Error:', e.message);
  if (e.stdout) console.log('stdout:', e.stdout);
  if (e.stderr) console.log('stderr:', e.stderr);
}
