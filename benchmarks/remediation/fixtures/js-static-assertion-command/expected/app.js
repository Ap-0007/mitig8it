const { execSync, execFileSync } = require('node:child_process');
const yaml = require('js-yaml');
const config = yaml.load('bin: convert');
function resize(name) {
  return execFileSync('convert', [name, '-resize', '50%', 'out.png']);
}
module.exports = { resize, config };
