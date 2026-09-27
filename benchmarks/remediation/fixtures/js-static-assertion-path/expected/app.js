const path = require('node:path');
const fs = require('node:fs');
const yaml = require('js-yaml');
const config = yaml.load('root: /srv/uploads');
const BASE = '/srv/uploads';
function readUpload(req) {
  const name = req.query.name;
  const baseDir = path.resolve(BASE);
  const target = path.resolve(baseDir, String(name));
  if (target !== baseDir && !target.startsWith(baseDir + path.sep)) throw new Error('path escapes base directory');
  return fs.readFileSync(target, 'utf8');
}
module.exports = { readUpload, config };
