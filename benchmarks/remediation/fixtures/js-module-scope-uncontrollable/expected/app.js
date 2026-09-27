// The archive is named after the account the job runs as, read once when this module is
// required. There is no function to call and no input a test can set: the account comes from a
// call that happens on import, so nothing a generated proof does changes what reaches the
// command. The service refuses to write a proof, as module_scope_source_not_controllable, and
// the repair is therefore asserted statically rather than executed.
const { execSync, execFileSync } = require('child_process');
const os = require('node:os');

const account = os.userInfo().username;
const archive = execFileSync('tar', ['-czf', `/backup/${account}.tgz`, `/srv/${account}`]).toString();

module.exports = { archive, account };
