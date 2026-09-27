// The trusted check for a fixture whose repair is verified by a static assertion.
//
// It reads source text and parses it. It never loads the module, and that is the point rather
// than a shortcut: this file requires `js-yaml`, which the sandbox has no copy of, so the module
// cannot be loaded and the service refuses to write a behavioural proof for it
// (`dependency_not_available_in_sandbox:js-yaml`). A source-text check is the same class of claim
// as the static assertion it audits, and it is deliberately not called a proof of behaviour.
//
// Three invocation modes.
//   node tests/verify.js --exploit | --behavior   Sandbox mode: checks the app.js in this tree.
//   node tests/verify.js <original> <repaired>    Harness mode: compares the checked-in trees.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const LITERAL = 'sk-live-7f3a91bc44de2210';
const ENVIRONMENT_READ = 'process.env.API_KEY';
const EXPORTS = 'module.exports = { apiKey, settings, authHeaders };';

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

function exploit() {
  const text = source(localPath());
  if (text.includes(LITERAL) || !text.includes(ENVIRONMENT_READ)) {
    process.stderr.write('vulnerability present: the API key is a literal in the source, not read from the environment\n');
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
  assert.ok(original.includes(LITERAL), 'the original does not carry the literal');
  assert.ok(!repaired.includes(LITERAL), 'the repair still carries the literal');
  assert.ok(repaired.includes(ENVIRONMENT_READ), 'the repair does not read the environment');
  assert.ok(parses(original) && parses(repaired));
  assert.ok(repaired.includes(EXPORTS), 'the repair changed the module surface');
  process.stdout.write(JSON.stringify({ vulnerability_observed: true, behavior_preserved: true }));
}

const mode = process.argv[2];
if (mode === '--exploit') exploit();
else if (mode === '--behavior') behavior();
else compare(process.argv[2], process.argv[3]);
