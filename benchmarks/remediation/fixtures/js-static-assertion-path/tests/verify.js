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

// The unguarded join the finding reports, and the containment the repair has to add: resolve
// against the base directory, then refuse anything that does not stay under it. A `path.basename`
// defence would not satisfy this, which is correct: the taint rule does not accept one either.
const UNGUARDED_READ = "fs.readFileSync(path.join(BASE, name), 'utf8')";
const RESOLVES = 'path.resolve(baseDir, String(name))';
const REFUSES_OUTSIDE = "!target.startsWith(baseDir + path.sep)";
const EXPORTS = 'module.exports = { readUpload, config };';

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

function contained(text) {
  return !text.includes(UNGUARDED_READ) && text.includes(RESOLVES) && text.includes(REFUSES_OUTSIDE);
}

function exploit() {
  const text = source(localPath());
  if (!contained(text)) {
    process.stderr.write('vulnerability present: the read joins a caller-supplied name to the base directory with no containment check\n');
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
  assert.ok(original.includes(UNGUARDED_READ), 'the original does not carry the unguarded read');
  assert.ok(contained(repaired), 'the repair does not resolve and contain the path');
  assert.ok(parses(original) && parses(repaired));
  assert.ok(repaired.includes(EXPORTS), 'the repair changed the module surface');
  process.stdout.write(JSON.stringify({ vulnerability_observed: true, behavior_preserved: true }));
}

const mode = process.argv[2];
if (mode === '--exploit') exploit();
else if (mode === '--behavior') behavior();
else compare(process.argv[2], process.argv[3]);
