const KeetaNet = require('@keetanetwork/keetanet-client');
const crypto = require('crypto');
const bip39 = require('bip39');
const logger = require('../utils/logger');

/**
 * Generate a new wallet using KeetaNet SDK with BIP39 mnemonic phrase
 * @returns {Object} Wallet object with mnemonic, seed, publicKey, and address
 */
const createWallet = () => {
  try {
    // Generate a 256-bit entropy for 24-word mnemonic (KeetaNet requires 32 bytes)
    const entropy = crypto.randomBytes(32); // 256 bits = 32 bytes
    
    // Generate BIP39 mnemonic phrase from entropy
    const mnemonic = bip39.entropyToMnemonic(entropy.toString('hex'));
    
    // Convert mnemonic back to entropy to get the exact seed bytes
    // This ensures we have exactly 32 bytes (256 bits) for KeetaNet
    const mnemonicEntropy = bip39.mnemonicToEntropy(mnemonic);
    const seed = mnemonicEntropy; // Use the entropy as the seed for KeetaNet (32 bytes hex = 64 chars)
    
    // Create an account using the generated seed (index 0)
    const account = KeetaNet.lib.Account.fromSeed(seed, 0);
    
    return {
      mnemonic: mnemonic, // 24-word mnemonic phrase
      seed: seed, // Hex seed derived from mnemonic (256 bits)
      publicKey: account.publicKeyString.toString(),
      address: account.publicKeyString.toString(), // In KeetaNet, public key serves as address
    };
  } catch (error) {
    logger.error({ error }, 'Error creating wallet');
    const httpError = new Error('Failed to create wallet: ' + error.message);
    httpError.status = 500;
    throw httpError;
  }
};

/**
 * Import wallet from seed
 * @param {string} seed - The seed string
 * @returns {Object} Wallet object with publicKey and address
 */
const importWalletFromSeed = (seed) => {
  try {
    if (!seed || typeof seed !== 'string' || seed.trim().length === 0) {
      const error = new Error('Invalid seed: Seed is required');
      error.status = 400;
      throw error;
    }

    // Create an account from the seed (index 0)
    const account = KeetaNet.lib.Account.fromSeed(seed.trim(), 0);
    
    return {
      publicKey: account.publicKeyString.toString(),
      address: account.publicKeyString.toString(), // In KeetaNet, public key serves as address
    };
  } catch (error) {
    logger.error({ error }, 'Error importing wallet from seed');
    if (error.status) {
      throw error;
    }
    const httpError = new Error('Failed to import wallet: ' + error.message);
    httpError.status = 400;
    throw httpError;
  }
};

/**
 * Import wallet from BIP39 mnemonic phrase
 * @param {string} mnemonic - The BIP39 mnemonic phrase
 * @returns {Object} Wallet object with publicKey and address
 */
const importWalletFromMnemonic = (mnemonic) => {
  try {
    if (!mnemonic || typeof mnemonic !== 'string' || mnemonic.trim().length === 0) {
      const error = new Error('Invalid mnemonic phrase');
      error.status = 400;
      throw error;
    }

    const trimmedMnemonic = mnemonic.trim();
    
    // Validate BIP39 mnemonic
    if (!bip39.validateMnemonic(trimmedMnemonic)) {
      const error = new Error('Invalid BIP39 mnemonic phrase. Please check your words and try again.');
      error.status = 400;
      throw error;
    }

    // Convert mnemonic to entropy (seed) for KeetaNet
    const seed = bip39.mnemonicToEntropy(trimmedMnemonic);
    
    // Create an account from the seed (index 0)
    const account = KeetaNet.lib.Account.fromSeed(seed, 0);
    
    return {
      publicKey: account.publicKeyString.toString(),
      address: account.publicKeyString.toString(),
    };
  } catch (error) {
    logger.error({ error }, 'Error importing wallet from mnemonic');
    if (error.status) {
      throw error;
    }
    const httpError = new Error('Failed to import wallet: ' + error.message);
    httpError.status = 400;
    throw httpError;
  }
};

/**
 * Import wallet from private key
 * Note: KeetaNet uses seeds, but we can try to derive from private key if possible
 * @param {string} privateKey - The private key (treated as seed)
 * @returns {Object} Wallet object with address
 */
const importWalletFromPrivateKey = (privateKey) => {
  try {
    if (!privateKey || typeof privateKey !== 'string' || privateKey.trim().length === 0) {
      const error = new Error('Invalid private key');
      error.status = 400;
      throw error;
    }

    // In KeetaNet, we primarily use seeds. For private key import,
    // we'll treat it as a seed string
    const account = KeetaNet.lib.Account.fromSeed(privateKey.trim(), 0);
    
    return {
      publicKey: account.publicKeyString.toString(),
      address: account.publicKeyString.toString(),
    };
  } catch (error) {
    logger.error({ error }, 'Error importing wallet from private key');
    if (error.status) {
      throw error;
    }
    const httpError = new Error('Failed to import wallet: Invalid private key or seed');
    httpError.status = 400;
    throw httpError;
  }
};

/**
 * Encrypt wallet data
 * @param {string} data - Data to encrypt
 * @param {string} password - Encryption password
 * @returns {string} Encrypted data
 */
const encryptWalletData = (data, password) => {
  try {
    const algorithm = 'aes-256-gcm';
    const key = crypto.scryptSync(password, 'salt', 32);
    const iv = crypto.randomBytes(16);
    
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag();
    
    return {
      encrypted,
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex'),
    };
  } catch (error) {
    logger.error({ error }, 'Error encrypting wallet data');
    throw new Error('Failed to encrypt wallet data');
  }
};

/**
 * Decrypt wallet data
 * @param {Object} encryptedData - Encrypted data object
 * @param {string} password - Decryption password
 * @returns {string} Decrypted data
 */
const decryptWalletData = (encryptedData, password) => {
  try {
    const algorithm = 'aes-256-gcm';
    const key = crypto.scryptSync(password, 'salt', 32);
    const iv = Buffer.from(encryptedData.iv, 'hex');
    const authTag = Buffer.from(encryptedData.authTag, 'hex');
    
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    decipher.setAuthTag(authTag);
    
    let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  } catch (error) {
    logger.error({ error }, 'Error decrypting wallet data');
    throw new Error('Failed to decrypt wallet data');
  }
};

/**
 * Get account balance and tokens
 * @param {string} address - The account address (public key)
 * @returns {Object} Account balance and token information
 */
const getAccountBalance = async (address) => {
  try {
    if (!address || typeof address !== 'string' || address.trim().length === 0) {
      const error = new Error('Invalid address: Address is required');
      error.status = 400;
      throw error;
    }

    // Initialize KeetaNet UserClient
    // Note: Configure with your actual network endpoint
    const networkEndpoint = process.env.KEETANET_ENDPOINT || 'https://api.keeta.network';
    
    const client = await new KeetaNet.lib.UserClientBuilder()
      .withNetworkEndpoint(networkEndpoint)
      .build();

    // Get account state
    const accountState = await client.getAccountState(address.trim());
    
    // Extract balance and token information
    // KeetaNet uses balances object where keys are token addresses
    const balances = accountState.balances || {};
    const tokens = Object.keys(balances).map(tokenAddress => ({
      address: tokenAddress,
      balance: balances[tokenAddress]?.toString() || '0',
    }));

    // Calculate total balance (sum of all token balances)
    const totalBalance = Object.values(balances).reduce((sum, balance) => {
      const balanceValue = typeof balance === 'string' ? parseFloat(balance) : (balance || 0);
      return sum + (isNaN(balanceValue) ? 0 : balanceValue);
    }, 0);

    return {
      address: address.trim(),
      balances: balances,
      tokens: tokens,
      totalBalance: totalBalance,
    };
  } catch (error) {
    logger.error({ error, address }, 'Error getting account balance');
    
    // If SDK fails, return empty data structure for now
    // In production, you'd want proper error handling
    if (error.message && error.message.includes('network') || error.message.includes('connection')) {
      // Return empty structure if network error
      return {
        address: address.trim(),
        balances: {},
        tokens: [],
        totalBalance: 0,
      };
    }
    
    if (error.status) {
      throw error;
    }
    const httpError = new Error('Failed to get account balance: ' + error.message);
    httpError.status = 500;
    throw httpError;
  }
};

/**
 * Get account info
 * @param {string} address - The account address (public key)
 * @returns {Object} Account information
 */
const getAccountInfo = async (address) => {
  try {
    if (!address || typeof address !== 'string' || address.trim().length === 0) {
      const error = new Error('Invalid address: Address is required');
      error.status = 400;
      throw error;
    }

    // Initialize KeetaNet UserClient
    const networkEndpoint = process.env.KEETANET_ENDPOINT || 'https://api.keeta.network';
    
    const client = await new KeetaNet.lib.UserClientBuilder()
      .withNetworkEndpoint(networkEndpoint)
      .build();

    // Get account state
    const accountState = await client.getAccountState(address.trim());
    
    return {
      address: address.trim(),
      publicKey: address.trim(),
      info: accountState.info || {},
      representative: accountState.representative || null,
      permissions: accountState.permissions || {},
    };
  } catch (error) {
    logger.error({ error, address }, 'Error getting account info');
    
    if (error.status) {
      throw error;
    }
    const httpError = new Error('Failed to get account info: ' + error.message);
    httpError.status = 500;
    throw httpError;
  }
};

module.exports = {
  createWallet,
  importWalletFromSeed,
  importWalletFromMnemonic,
  importWalletFromPrivateKey,
  encryptWalletData,
  decryptWalletData,
  getAccountBalance,
  getAccountInfo,
};

