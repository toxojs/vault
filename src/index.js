const certificateVault = require('./certificate-vault');
const fileCertificateVault = require('./file-certificate-vault');
const databaseCertificateVault = require('./database-certificate-vault');
const generatePassphrase = require('./generate-passphrase');
const generateCertificate = require('./generate-certificate');
const generateTenant = require('./generate-tenant');

module.exports = {
  ...certificateVault,
  ...fileCertificateVault,
  ...databaseCertificateVault,
  ...generatePassphrase,
  ...generateCertificate,
  ...generateTenant,
};
