const jwt = require('jsonwebtoken');
const { ioc } = require('@toxo/ioc');

const logger = ioc.get('logger');

class CertificateVault {
  constructor() {
    this.vaultInfo = new Map();
  }

  // eslint-disable-next-line class-methods-use-this
  innerGetPublicKey(tenantId) {
    throw new Error(`No existing public key for tenant ${tenantId}`);
  }

  // eslint-disable-next-line class-methods-use-this
  innerGetPrivateKey(tenantId) {
    throw new Error(`No existing private key for tenant ${tenantId}`);
  }

  // eslint-disable-next-line class-methods-use-this
  innerGetOptions(tenantId) {
    throw new Error(`No existing vault options for tenant ${tenantId}`);
  }

  async getPublicKey(tenantId) {
    if (!this.vaultInfo.has(tenantId)) {
      this.vaultInfo.set(tenantId, {
        privateKey: undefined,
        publicKey: undefined,
        options: undefined,
      });
    }
    const info = this.vaultInfo.get(tenantId);
    if (!info.publicKey) {
      try {
        info.publicKey = await this.innerGetPublicKey(tenantId);
      } catch (err) {
        logger.warn(err);
        throw err;
      }
    }
    return info.publicKey;
  }

  async getPrivateKey(tenantId) {
    if (!this.vaultInfo.has(tenantId)) {
      this.vaultInfo.set(tenantId, {
        privateKey: undefined,
        publicKey: undefined,
        options: undefined,
      });
    }
    const info = this.vaultInfo.get(tenantId);
    if (!info.privateKey) {
      try {
        info.privateKey = await this.innerGetPrivateKey(tenantId);
      } catch (err) {
        logger.warn(err);
        throw err;
      }
    }
    return info.privateKey;
  }

  async getOptions(tenantId) {
    if (!this.vaultInfo.has(tenantId)) {
      this.vaultInfo.set(tenantId, {
        privateKey: undefined,
        publicKey: undefined,
        options: undefined,
      });
    }
    const info = this.vaultInfo.get(tenantId);
    if (!info.options) {
      try {
        info.options = await this.innerGetOptions(tenantId);
      } catch (err) {
        logger.warn(err);
        throw err;
      }
    }
    return info.options;
  }

  async generateToken(payload, tenantId) {
    try {
      const key = await this.getPrivateKey(tenantId);
      const options = await this.getOptions(tenantId);
      const jwtOptions = {
        algorithm: options.algorithm,
        expiresIn: options.lifetime,
        header: { kid: tenantId },
      };
      const { passphrase } = options;
      return await new Promise((resolve, reject) => {
        jwt.sign(payload, { key, passphrase }, jwtOptions, (err, token) => {
          if (err) {
            return reject(err);
          }
          return resolve({ token, lifetimeSeconds: options.lifetimeSeconds });
        });
      });
    } catch (err) {
      return Promise.reject(err);
    }
  }

  async verifyToken(token) {
    try {
      const decoded = jwt.decode(token, { complete: true });
      const { header } = decoded;
      const tenantId = header.kid;
      if (!tenantId) {
        return Promise.reject(new Error('No KID found in token'));
      }
      const key = await this.getPublicKey(tenantId);
      return await new Promise((resolve, reject) => {
        jwt.verify(token, key, (err, payload) => {
          if (err) {
            return reject(err);
          }
          return resolve({ tenantId, payload });
        });
      });
    } catch (err) {
      return Promise.reject(err);
    }
  }

  clearVault() {
    this.vaultInfo.clear();
  }
}

module.exports = {
  CertificateVault,
};
