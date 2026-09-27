const yaml = require('js-yaml');
const apiKey = process.env.API_KEY;
const settings = yaml.load('retries: 3');
function authHeaders() {
  return { Authorization: `Bearer ${apiKey}` };
}
module.exports = { apiKey, settings, authHeaders };
