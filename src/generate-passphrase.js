const crypto = require('crypto');

const generatePassphrase = () => crypto.randomBytes(20).toString('hex');

module.exports = {
  generatePassphrase,
};
