const { ioc } = require('@toxo/ioc');
const { ensureDecryptedWithKey } = require('@toxo/encryption');
const { CertificateVault } = require('./certificate-vault');

const logger = ioc.get('logger');

class DatabaseCertificateVault extends CertificateVault {
  constructor(settings = {}) {
    super();
    if (!settings.collection) {
      const databaseManager = ioc.get('databaseManager');
      const database = databaseManager.get(settings.databaseName);
      this.collection = database.getCollection(
        settings.collectionName || 'tenants'
      );
    } else {
      this.collection = settings.collection;
    }
    this.secretKey = settings.secretKey;
  }

  getTenant(tenantId) {
    return this.collection.findONe({ tenantId });
  }

  async innerGetPublicKey(tenantId) {
    const tenant = await this.getTenant(tenantId);
    if (!tenant) {
      logger.error(`No public key for tenant ${tenantId}`);
      throw new Error(`No existing public key for tenant ${tenantId}`);
    }
    return this.secretKey
      ? ensureDecryptedWithKey(this.secretKey, tenant.publicKey)
      : tenant.publicKey;
  }

  async innerGetPrivateKey(tenantId) {
    const tenant = await this.getTenant(tenantId);
    if (!tenant) {
      logger.error(`No private key for tenant ${tenantId}`);
      throw new Error(`No existing private key for tenant ${tenantId}`);
    }
    const { privateKey } = tenant;
    return this.secretKey
      ? ensureDecryptedWithKey(this.secretKey, privateKey)
      : privateKey;
  }

  async innerGetOptions(tenantId) {
    const tenant = await this.getTenant(tenantId);
    if (!tenant) {
      logger.error(`No vault options for tenant ${tenantId}`);
      throw new Error(`No existing vault options for tenant ${tenantId}`);
    }
    return {
      id: tenant.tenantId,
      name: tenant.name,
      algorithm: tenant.algorithm,
      lifetime: tenant.lifetime,
      lifetimeSeconds: tenant.lifetimeSeconds,
      passphrase: this.secretKey
        ? ensureDecryptedWithKey(this.secretKey, tenant.passphrase)
        : tenant.passphrase,
    };
  }
}

module.exports = {
  DatabaseCertificateVault,
};
