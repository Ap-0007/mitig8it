// The trusted check for a fixture whose repair is verified by a static assertion.
//
// It reads source text and parses it. It never loads the module, and that is the point rather
// than a shortcut: this file requires `js-yaml`, which the sandbox has no copy of, so the module
// cannot be loaded and the service refuses to write a behavioural proof for it
// (`dependency_not_available_in_sandbox:js-yaml`). A source-text check is the same class of claim
// as the static assertion it audits, and it is deliberately not called a proof of behaviour.
//
// This fixture is also the one whose repair changes a line the finding's region does not cover:
// the import on line 1 has to gain `execFileSync`. The repair declares that line by carrying a
// hunk there, which is what clause 3 of the static assertion allows and how it allows it.
//
// Three invocation modes.
//   node tests/verify.js --exploit | --behavior   Sandbox mode: checks the app.js in this tree.
//   node tests/verify.js <original> <repaired>    Harness mode: compares the checked-in trees.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

// The shell string the finding reports, and the argument array the repair has to replace it with.
const SHELL_STRING = 'execSync(`convert ${name} -resize 50% out.png`)';
const ARGUMENT_ARRAY = "execFileSync('convert', [name, '-resize', '50%', 'out.png'])";
const IMPORTS_EXEC_FILE = 'execFileSync } = require';
const EXPORTS = 'module.exports = { resize, config };';

function localPath() {
  return path.resolve(__dirname, '..', 'app.js');
}

function source(file) {
  return fs.readFileSync(path.resolve(file), 'utf8');
}

// Parses without running: a repair that produced a file Node cannot parse is not a repair.
function parses(text) {
  try {
    new vm.Script(text, { filename: 'app.js' });
    return true;
  } catch {
    return false;
  }
}

function argumentised(text) {
  return !text.includes(SHELL_STRING) && text.includes(ARGUMENT_ARRAY) && text.includes(IMPORTS_EXEC_FILE);
}

function exploit() {
  const text = source(localPath());
  if (!argumentised(text)) {
    process.stderr.write('vulnerability present: a caller-supplied name is interpolated into a command string run through a shell\n');
    process.exit(1);
  }
  process.exit(0);
}

function behavior() {
  const text = source(localPath());
  assert.ok(parses(text), 'the file no longer parses');
  assert.ok(text.includes(EXPORTS), 'the module no longer exports the same names');
  process.exit(0);
}

function compare(originalPath, repairedPath) {
  const original = source(originalPath);
  const repaired = source(repairedPath);
  assert.ok(original.includes(SHELL_STRING), 'the original does not carry the shell command string');
  assert.ok(argumentised(repaired), 'the repair does not pass the name as its own argument');
  assert.ok(parses(original) && parses(repaired));
  assert.ok(repaired.includes(EXPORTS), 'the repair changed the module surface');
  process.stdout.write(JSON.stringify({ vulnerability_observed: true, behavior_preserved: true }));
}

const mode = process.argv[2];
if (mode === '--exploit') exploit();
else if (mode === '--behavior') behavior();
else compare(process.argv[2], process.argv[3]);
