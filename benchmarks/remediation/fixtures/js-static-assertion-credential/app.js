const yaml = require('js-yaml');
const apiKey = 'sk-live-7f3a91bc44de2210';
const settings = yaml.load('retries: 3');
function authHeaders() {
  return { Authorization: `Bearer ${apiKey}` };
}
module.exports = { apiKey, settings, authHeaders };
