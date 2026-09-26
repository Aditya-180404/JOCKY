async function main() {
  const source = `investigation "quick_info" {
    collect system_info
    export evidence "quick_evidence.json"
}
`;

  console.log('Sending /api/compiler/run for quick_info...');
  const start = Date.now();
  const runRes = await fetch('http://localhost:8080/api/compiler/run', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      source,
      target: 'windows-x64'
    })
  }).then(r => r.json());

  console.log('Total HTTP turnaround:', Date.now() - start, 'ms');
  console.log('Run response:', JSON.stringify(runRes, null, 2));
}

main().catch(console.error);
