const { spawn } = require('node:child_process');
const child = spawn(process.execPath, [require('node:path').resolve(__dirname, '../server.cjs')], { stdio: 'inherit', env: process.env });
for (const signal of ['SIGTERM', 'SIGINT']) process.once(signal, () => child.kill(signal));
child.once('exit', code => process.exit(code || 0));
