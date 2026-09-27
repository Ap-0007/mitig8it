// Which affected files a repair can even be attempted on.
//
// The repair service decides support per finding from the affected file's language
// (`services/remediation-service/src/families.py`): a suffix outside these sets has
// no toolchain that could check a repair, so the finding is skipped with
// `unsupported_language`. That decision used to be taken only inside the repair service,
// which meant a job whose selection mixed supported and unsupported files spent its
// snapshot stage on files the immutable tree does not carry and failed as a whole, taking
// the supported findings of the same pull request down with it.
//
// The control plane therefore mirrors the same suffix sets here and never selects an
// unsupported finding into a job in the first place; the excluded findings are recorded on
// the job as ordinary per-finding skips. `tests/remediationLanguages.test.js` reads
// `families.py` and fails if the two ever drift apart.
const JAVASCRIPT = 'javascript';
const PYTHON = 'python';
const WORKFLOW = 'workflow';

const JAVASCRIPT_SUFFIXES = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs']);
const PYTHON_SUFFIXES = new Set(['.py']);
// A workflow is a language here because the workflow_hardening family repairs one, and it
// is decided by path rather than by suffix alone: a `.yml` file anywhere else is ordinary
// YAML that these templates must never be handed. Mirrors WORKFLOW_SUFFIXES and
// WORKFLOW_DIRECTORY in families.py.
const WORKFLOW_SUFFIXES = new Set(['.yml', '.yaml']);
const WORKFLOW_DIRECTORY = '.github/workflows/';

const UNSUPPORTED_LANGUAGE_CODE = 'unsupported_language';
// The repair service's own wording for this skip (`gates.UNSUPPORTED_LANGUAGE_MESSAGE`),
// so a finding excluded at selection and a finding excluded inside the engine read
// identically in the `No automatic fix:` line on the pull request.
const UNSUPPORTED_LANGUAGE_MESSAGE =
  'The affected file is neither JavaScript/TypeScript nor Python, so no toolchain can check a repair of it.';

// Skips decided before or around the repair call rather than by the repair service. They
// are written to the job when they are decided, so they outlive the stage that found them.
const SELECTION_STAGE = 'selection';
const SNAPSHOT_STAGE = 'snapshot';
const CARRIED_SKIP_STAGES = new Set([SELECTION_STAGE, SNAPSHOT_STAGE]);

// PurePosixPath(...).suffix, so a dotfile such as `.py` has no suffix, exactly as the
// repair service reads it.
function suffixOf(path) {
  const name = String(path || '').split('/').pop();
  const dot = name.lastIndexOf('.');
  return dot > 0 ? name.slice(dot).toLowerCase() : '';
}

// families.py `is_workflow_path`: the suffix and the directory both have to hold.
function isWorkflowPath(path) {
  if (!path) return false;
  const normalized = String(path).replace(/\\/g, '/').toLowerCase();
  if (!WORKFLOW_SUFFIXES.has(suffixOf(normalized))) return false;
  return normalized.startsWith(WORKFLOW_DIRECTORY) || normalized.includes(`/${WORKFLOW_DIRECTORY}`);
}

function languageOfPath(path) {
  if (!path) return null;
  const suffix = suffixOf(path);
  if (JAVASCRIPT_SUFFIXES.has(suffix)) return JAVASCRIPT;
  if (PYTHON_SUFFIXES.has(suffix)) return PYTHON;
  if (isWorkflowPath(path)) return WORKFLOW;
  return null;
}

function isRemediablePath(path) {
  return languageOfPath(path) !== null;
}

// Split findings into the ones a repair can be attempted on and the ones that have no
// toolchain, keeping input order within each side so a caller's severity ordering holds.
function partitionBySupportedLanguage(rows, pathOf) {
  const supported = [];
  const unsupported = [];
  for (const row of rows) (isRemediablePath(pathOf(row)) ? supported : unsupported).push(row);
  return { supported, unsupported };
}

function unsupportedLanguageSkip(findingId) {
  return { finding_id: String(findingId), code: UNSUPPORTED_LANGUAGE_CODE, message: UNSUPPORTED_LANGUAGE_MESSAGE, stage: SELECTION_STAGE };
}

module.exports = {
  JAVASCRIPT, PYTHON, WORKFLOW, JAVASCRIPT_SUFFIXES, PYTHON_SUFFIXES, WORKFLOW_SUFFIXES, WORKFLOW_DIRECTORY,
  UNSUPPORTED_LANGUAGE_CODE, UNSUPPORTED_LANGUAGE_MESSAGE,
  SELECTION_STAGE, SNAPSHOT_STAGE, CARRIED_SKIP_STAGES,
  languageOfPath, isWorkflowPath, isRemediablePath, partitionBySupportedLanguage, unsupportedLanguageSkip,
};
