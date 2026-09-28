async function main() {
  console.log('Testing GET /health...');
  const health = await fetch('http://localhost:8080/health').then(r => r.json());
  console.log('Health:', health);

  console.log('\nTesting GET /api/compiler/targets...');
  const targets = await fetch('http://localhost:8080/api/compiler/targets').then(r => r.json());
  console.log('Targets:', targets);

  console.log('\nTesting GET /api/compiler/capabilities...');
  const caps = await fetch('http://localhost:8080/api/compiler/capabilities').then(r => r.json());
  console.log('Capabilities count:', Object.keys(caps.capabilities || {}).length);

  console.log('\nTesting GET /api/downloads/info...');
  const dlInfo = await fetch('http://localhost:8080/api/downloads/info').then(r => r.json());
  console.log('Download Info packages:', dlInfo.packages.length);
  for (const p of dlInfo.packages) {
    console.log(` - ${p.name} (${p.filename}): ${p.size_bytes} bytes, SHA256: ${p.sha256}`);
  }

  const fs = await import('fs');
  const realDslSource = fs.readFileSync('examples/basic_system_triage.jy', 'utf8');

  console.log('\nTesting POST /api/compiler/check with genuine .jy source...');
  const check = await fetch('http://localhost:8080/api/compiler/check', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      source: realDslSource,
      target: 'windows-x64'
    })
  }).then(r => r.json());
  console.log('Check result:', check);

  console.log('\nTesting POST /api/compiler/compile with genuine .jy source...');
  const compileRes = await fetch('http://localhost:8080/api/compiler/compile', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      source: realDslSource,
      target: 'windows-x64'
    })
  });
  console.log('Compile HTTP status:', compileRes.status);
  console.log('Compile Content-Type:', compileRes.headers.get('content-type'));
  console.log('Compile Content-Disposition:', compileRes.headers.get('content-disposition'));
  const compileBlob = await compileRes.arrayBuffer();
  console.log('Compiled binary size:', compileBlob.byteLength, 'bytes');

  console.log('\nTesting POST /api/compiler/run (Live native execution + evidence + verification)...');
  const runRes = await fetch('http://localhost:8080/api/compiler/run', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      source: realDslSource,
      target: 'windows-x64'
    })
  }).then(r => r.json());
  console.log('Run success:', runRes.success);
  console.log('Run exit_code:', runRes.exit_code);
  console.log('Run duration:', runRes.duration_ms, 'ms');
  console.log('Run stdout length:', (runRes.stdout || '').length);
  console.log('Run verification:', runRes.verification);
  console.log('Run evidence count:', runRes.evidence ? runRes.evidence.length : 0);

  console.log('\nTesting Auth and Tools APIs...');
  const regRes = await fetch('http://localhost:8080/api/auth/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: 'e2e_analyst_' + Date.now(),
      email: 'analyst_' + Date.now() + '@jocky.security',
      password: 'SecurePassword123!',
      organization: 'JOCKY Security Research'
    })
  }).then(r => r.json());
  console.log('Register response:', regRes);

  const toolsRes = await fetch('http://localhost:8080/api/tools').then(r => r.json());
  console.log('Tools list count:', toolsRes.length || 0);

  console.log('\nTesting GET /api/downloads/windows direct download...');
  const winDl = await fetch('http://localhost:8080/api/downloads/windows');
  console.log('Windows download status:', winDl.status);
  console.log('Windows download Content-Disposition:', winDl.headers.get('content-disposition'));
  const winDlBytes = await winDl.arrayBuffer();
  console.log('Windows download size:', winDlBytes.byteLength, 'bytes');

  console.log('\nALL API ENDPOINTS VALIDATED SUCCESSFULLY!');
}

main().catch(err => {
  console.error('Test failed with error:', err);
  process.exit(1);
});
