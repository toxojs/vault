const fs = require('fs');
const path = require('path');
const { ensureDecryptedWithKey } = require('@toxo/encryption');
const { CertificateVault } = require('./certificate-vault');

class FileCertificateVault extends CertificateVault {
  constructor(settings = {}) {
    super();
    this.secretKey = settings.secretKey;
  }

  static getFile(tenantId, part) {
    const vaultDir = process.env.VAULT_DIR || './data/vault';
    const fileName = path.join(vaultDir, tenantId, part);
    return fs.readFileSync(fileName, 'utf-8');
  }

  async innerGetPublicKey(tenantId) {
    try {
      const file = FileCertificateVault.getFile(tenantId, 'public.key');
      return this.secretKey
        ? ensureDecryptedWithKey(this.secretKey, file)
        : file;
    } catch (err) {
      throw new Error(`No existing public key for tenant ${tenantId}`);
    }
  }

  async innerGetPrivateKey(tenantId) {
    try {
      const file = FileCertificateVault.getFile(tenantId, 'private.key');
      return this.secretKey
        ? ensureDecryptedWithKey(this.secretKey, file)
        : file;
    } catch (err) {
      throw new Error(`No existing private key for tenant ${tenantId}`);
    }
  }

  async innerGetOptions(tenantId) {
    try {
      const file = FileCertificateVault.getFile(tenantId, 'options.json');
      const options = JSON.parse(file);
      if (this.secretKey) {
        options.passphrase = ensureDecryptedWithKey(
          this.secretKey,
          options.passphrase
        );
      }
      return options;
    } catch (err) {
      throw new Error(`No existing options for tenant ${tenantId}`);
    }
  }
}

module.exports = {
  FileCertificateVault,
};
