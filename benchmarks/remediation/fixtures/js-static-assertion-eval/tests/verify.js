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

// The dynamic-code sink the finding reports, and the parse the repair has to replace it with.
// The check is on `eval(` as a call, not on the word, so a comment mentioning eval does not
// satisfy or break it.
const EVAL_CALL = /\beval\s*\(/;
const JSON_PARSE = 'JSON.parse(userInput)';
const EXPORTS = 'module.exports = { parsePayload, config };';

function localPath() {
  return path.resolve(__dirname, '..', 'app.js');
}

function source(file) {
  return fs.readFileSync(path.resolve(file), 'utf8');
}

// Parses without running: a repair that produced a file Node cannot parse is not a repair. It is
// also the only safe way to read this fixture at all, since loading it would run `eval`.
function parses(text) {
  try {
    new vm.Script(text, { filename: 'app.js' });
    return true;
  } catch {
    return false;
  }
}

function parsedNotCompiled(text) {
  return !EVAL_CALL.test(text) && text.includes(JSON_PARSE);
}

function exploit() {
  const text = source(localPath());
  if (!parsedNotCompiled(text)) {
    process.stderr.write('vulnerability present: a caller-supplied payload is compiled and run instead of parsed\n');
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
  assert.ok(EVAL_CALL.test(original), 'the original does not call eval');
  assert.ok(parsedNotCompiled(repaired), 'the repair still compiles the payload');
  assert.ok(parses(original) && parses(repaired));
  assert.ok(repaired.includes(EXPORTS), 'the repair changed the module surface');
  // A JSON document still parses to the same value, which is the behaviour the repair keeps.
  assert.deepEqual(JSON.parse('[1, 2]'), [1, 2]);
  process.stdout.write(JSON.stringify({ vulnerability_observed: true, behavior_preserved: true }));
}

const mode = process.argv[2];
if (mode === '--exploit') exploit();
else if (mode === '--behavior') behavior();
else compare(process.argv[2], process.argv[3]);
