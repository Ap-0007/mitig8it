const yaml = require('js-yaml');
const config = yaml.load('mode: strict');
function parsePayload(userInput) {
  return eval(userInput);
}
module.exports = { parsePayload, config };
