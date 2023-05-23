const crypto = require('crypto');

function generateCertificate(passphrase) {
  const keyOptions = {
    modulusLength: 1024 * 2,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem',
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
      cipher: 'aes-256-cbc',
      passphrase,
    },
  };
  return crypto.generateKeyPairSync('rsa', keyOptions);
}

module.exports = {
  generateCertificate,
};
