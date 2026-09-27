const path = require('node:path');
const fs = require('node:fs');
const yaml = require('js-yaml');
const config = yaml.load('root: /srv/uploads');
const BASE = '/srv/uploads';
function readUpload(req) {
  const name = req.query.name;
  return fs.readFileSync(path.join(BASE, name), 'utf8');
}
module.exports = { readUpload, config };
