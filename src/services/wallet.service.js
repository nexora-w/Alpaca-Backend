const KeetaNet = require('@keetanetwork/keetanet-client');
const crypto = require('crypto');
const bip39 = require('bip39');
const https = require('https');
const logger = require('../utils/logger');
const { serializeBigInt } = require('../utils/bigint-serializer');

const DEFAULT_NETWORK = process.env.KEETANET_NETWORK || 'test';
const NETWORK_ENDPOINT = process.env.KEETANET_ENDPOINT || 'https://api.keeta.network';
const LEDGER_ENDPOINT = process.env.KEETANET_LEDGER_ENDPOINT
  || 'https://rep3.main.network.api.keeta.com/api/node/ledger';

const TOKEN_NAME_REGEX = /^[A-Z_]{1,50}$/;
const TOKEN_SYMBOL_REGEX = /^[A-Z0-9_]{1,16}$/;

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
    
    const privateKey = seed; // In KeetaNet we treat the 32-byte seed as the deterministic private key

    return {
      mnemonic: mnemonic, // 24-word mnemonic phrase
      seed: seed, // Hex seed derived from mnemonic (256 bits)
      privateKey: privateKey,
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
      privateKey: seed.trim(),
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
      privateKey: seed,
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
    const normalizedKey = privateKey.trim();
    const account = KeetaNet.lib.Account.fromSeed(normalizedKey, 0);
    
    return {
      privateKey: normalizedKey,
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
 * Lightweight helper around https.get to retrieve JSON payloads.
 * Keeps dependencies small while supporting the remote ledger API.
 */
const fetchJson = (url) => new Promise((resolve, reject) => {
  const request = https.get(url, (response) => {
    if (response.statusCode && response.statusCode >= 400) {
      reject(new Error(`Ledger API request failed with status ${response.statusCode}`));
      response.resume();
      return;
    }

    let data = '';
    response.setEncoding('utf8');
    response.on('data', (chunk) => {
      data += chunk;
    });
    response.on('end', () => {
      try {
        resolve(JSON.parse(data));
      } catch (parseError) {
        reject(new Error('Failed to parse ledger API response'));
      }
    });
  });

  request.on('error', (err) => reject(err));
  request.end();
});

const hexToDecimalString = (hexValue) => {
  if (!hexValue) {
    return '0';
  }

  try {
    return BigInt(hexValue).toString();
  } catch (error) {
    logger.warn({ error, hexValue }, 'Failed to convert hex balance, returning raw string');
    return typeof hexValue === 'string' ? hexValue : '0';
  }
};

const normalizeBigIntInput = (value, label) => {
  try {
    const castValue = typeof value === 'string' ? value.trim() : value;
    const bigint = BigInt(castValue);

    if (bigint <= 0n) {
      const error = new Error(`${label} must be greater than zero`);
      error.status = 400;
      throw error;
    }

    return bigint;
  } catch (error) {
    if (!error.status) {
      const formattedError = new Error(`Invalid ${label}: must be a whole number`);
      formattedError.status = 400;
      throw formattedError;
    }
    throw error;
  }
};

const normalizeBuilderFriendlyError = (error) => {
  const response = {
    status: 500,
    message: 'Unexpected error while creating token',
    code: error?.code,
  };

  const message = error?.message || error?.toString() || '';

  if (/name does not fit proper format/i.test(message)) {
    return {
      status: 400,
      message: 'Token name must use uppercase letters or underscores (max 50 chars).',
      code: 'TOKEN_NAME_INVALID',
    };
  }

  if (/symbol does not fit proper format/i.test(message)) {
    return {
      status: 400,
      message: 'Token symbol must be uppercase alphanumeric or underscore (max 16 chars).',
      code: 'TOKEN_SYMBOL_INVALID',
    };
  }

  if (/resulting balance becomes negative/i.test(message)) {
    return {
      status: 400,
      message: 'Insufficient base token balance to pay the creation fee. Receive more funds and try again.',
      code: 'INSUFFICIENT_FUNDS',
    };
  }

  if (error?.code === 'NETWORK_TIMEOUT') {
    return {
      status: 504,
      message: 'KeetaNet representatives did not respond in time. Please retry.',
      code: 'NETWORK_TIMEOUT',
    };
  }

  if (error?.status && error.status >= 400 && error.status < 500) {
    return {
      status: error.status,
      message,
      code: error.code,
    };
  }

  return response;
};

const normalizeTransferError = (error) => {
  const defaultResponse = {
    status: 500,
    message: 'Failed to transfer tokens. Please try again.',
    code: error?.code || 'TRANSFER_FAILED',
  };

  const message = error?.message || '';

  if (/insufficient/i.test(message) || /resulting balance becomes negative/i.test(message)) {
    return {
      status: 400,
      message: 'Insufficient balance to complete this transfer.',
      code: 'INSUFFICIENT_FUNDS',
    };
  }

  if (/account/i.test(message) && /not found/i.test(message)) {
    return {
      status: 404,
      message: 'One of the accounts involved could not be found on the network.',
      code: 'ACCOUNT_NOT_FOUND',
    };
  }

  if (/network timeout/i.test(message)) {
    return {
      status: 504,
      message: 'KeetaNet representatives did not respond in time. Please retry.',
      code: 'NETWORK_TIMEOUT',
    };
  }

  if (error?.status && error.status >= 400 && error.status < 500) {
    return {
      status: error.status,
      message,
      code: error.code,
    };
  }

  return defaultResponse;
};

const getUserClient = (signerAccount, network) => {
  const clientOptions = NETWORK_ENDPOINT ? { networkEndpoint: NETWORK_ENDPOINT } : undefined;
  const targetNetwork = network || DEFAULT_NETWORK;
  return KeetaNet.UserClient.fromNetwork(targetNetwork, signerAccount, clientOptions);
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

    const normalizedAddress = address.trim();
    const url = `${LEDGER_ENDPOINT.replace(/\/$/, '')}/account/${encodeURIComponent(normalizedAddress)}/balance`;

    const ledgerResponse = await fetchJson(url);

    const tokens = (ledgerResponse.balances || []).map((tokenBalance) => {
      const balanceHex = tokenBalance.balance || '0x0';
      return {
        token: tokenBalance.token,
        balanceHex,
        balance: hexToDecimalString(balanceHex),
      };
    });

    const totalBalance = tokens.reduce((sum, tokenEntry) => {
      try {
        return sum + BigInt(tokenEntry.balance);
      } catch {
        return sum;
      }
    }, 0n).toString();

    // Serialize the response to convert any BigInt values to strings
    const response = {
      address: normalizedAddress,
      tokens,
      totalBalance,
      raw: ledgerResponse,
    };

    // Recursively serialize all BigInt values to strings for JSON compatibility
    return serializeBigInt(response);
  } catch (error) {
    logger.error({ error, address }, 'Error getting account balance from ledger API');

    if (error.status) {
      throw error;
    }
    const httpError = new Error('Failed to get account balance: ' + error.message);
    httpError.status = 502;
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
    const client = await new KeetaNet.lib.UserClientBuilder()
      .withNetworkEndpoint(NETWORK_ENDPOINT)
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

/**
 * Create a fungible token on the selected KeetaNet network
 * @param {Object} options
 * @param {string} options.seed - Hex seed/private key for signer
 * @param {string} options.name - Human readable name
 * @param {string} options.symbol - Symbol or ticker
 * @param {string|number|bigint} options.initialSupply - Total supply to mint
 * @param {string} [options.description] - Optional description
 * @param {Object} [options.metadata] - Additional metadata to embed
 * @returns {Promise<Object>} Token creation result
 */
const createToken = async ({
  seed,
  name,
  symbol,
  initialSupply,
  description,
  metadata = {},
  network,
}) => {
  try {
    if (!seed || typeof seed !== 'string' || seed.trim().length === 0) {
      const error = new Error('Seed is required to sign transactions');
      error.status = 400;
      throw error;
    }

    if (!name || !symbol) {
      const error = new Error('Token name and symbol are required');
      error.status = 400;
      throw error;
    }

    if (!TOKEN_NAME_REGEX.test(name)) {
      const error = new Error('Token name must use uppercase letters or underscores (max 50 chars).');
      error.status = 400;
      throw error;
    }

    if (!TOKEN_SYMBOL_REGEX.test(symbol)) {
      const error = new Error('Token symbol must be uppercase letters, numbers, or underscores (max 16 chars).');
      error.status = 400;
      throw error;
    }

    const signerSeed = seed.trim();
    const supplyBigInt = normalizeBigIntInput(initialSupply, 'initial supply');
    const signerAccount = KeetaNet.lib.Account.fromSeed(signerSeed, 0);

    const clientOptions = NETWORK_ENDPOINT ? { networkEndpoint: NETWORK_ENDPOINT } : undefined;
    const targetNetwork = network || DEFAULT_NETWORK;
    const client = KeetaNet.UserClient.fromNetwork(targetNetwork, signerAccount, clientOptions);

    const builder = client.initBuilder();
    builder.updateAccounts({
      account: signerAccount,
      signer: signerAccount,
    });

    const tokenAccount = builder.generateIdentifier(
      KeetaNet.lib.Account.AccountKeyAlgorithm.TOKEN,
      {
        account: signerAccount,
        signer: signerAccount,
      }
    );

    // Compute once so token address is available for subsequent operations
    await client.computeBuilderBlocks(builder);

    builder.modifyTokenSupply(supplyBigInt, { account: tokenAccount.account });

    const safeMetadata = metadata && typeof metadata === 'object' ? metadata : {};

    const metadataPayload = {
      name,
      symbol,
      description,
      ...safeMetadata,
    };

    const base64Metadata = Buffer.from(JSON.stringify(metadataPayload), 'utf8')
      .toString('base64');

    builder.setInfo({
      name,
      description: description || `${symbol} token created via Alpaca Wallet`,
      metadata: base64Metadata,
      defaultPermission: new KeetaNet.lib.Permissions(['ACCESS'], []),
    }, {
      account: tokenAccount.account,
    });

    const computed = await client.computeBuilderBlocks(builder);
    const publishResult = await client.publishBuilder(builder);

    // Serialize the response to convert any BigInt values to strings
    const response = {
      tokenAddress: tokenAccount.account.publicKeyString.get(),
      initialSupply: supplyBigInt.toString(),
      blocks: computed.blocks,
      publish: publishResult,
    };

    // Recursively serialize all BigInt values to strings for JSON compatibility
    return serializeBigInt(response);
  } catch (error) {
    const normalized = normalizeBuilderFriendlyError(error);
    logger.error({ error }, 'Error creating Keeta token');

    const httpError = new Error(normalized.message);
    httpError.status = normalized.status;
    httpError.code = normalized.code;
    throw httpError;
  }
};

/**
 * Transfer tokens using the KeetaNet send operation
 * @param {Object} options
 * @param {string} options.seed - Hex seed/private key for signer
 * @param {string} options.recipient - Recipient address/public key
 * @param {string|number|bigint} options.amount - Amount to transfer
 * @param {string} [options.tokenAddress] - Optional token identifier (defaults to base token)
 * @param {string} [options.network] - Optional network override
 * @returns {Promise<Object>} Transfer result
 */
const transferTokens = async ({
  seed,
  recipient,
  amount,
  tokenAddress,
  network,
}) => {
  try {
    if (!seed || typeof seed !== 'string' || seed.trim().length === 0) {
      const error = new Error('Seed is required to sign transactions');
      error.status = 400;
      throw error;
    }

    if (!recipient || typeof recipient !== 'string' || recipient.trim().length === 0) {
      const error = new Error('Recipient address is required');
      error.status = 400;
      throw error;
    }

    const sendAmount = normalizeBigIntInput(amount, 'amount');
    const signerSeed = seed.trim();
    const sender = KeetaNet.lib.Account.fromSeed(signerSeed, 0);

    // Determine target network (default to 'test' if not specified, matching sample)
    const targetNetwork = network || DEFAULT_NETWORK;

    // Create client - matching the working example pattern
    const client = KeetaNet.UserClient.fromNetwork(targetNetwork, sender);

    // Create recipient account from public key string - matching sample pattern
    const recipientAccount = KeetaNet.lib.Account.fromPublicKeyString(recipient.trim());

    // Initialize builder - matching sample pattern
    const builder = client.initBuilder();

    // Determine token for transfer (use baseToken if no tokenAddress provided)
    let tokenForTransfer = client.baseToken;
    if (tokenAddress && tokenAddress.trim().length > 0) {
      try {
        const tokenAccount = KeetaNet.lib.Account.fromPublicKeyString(tokenAddress.trim());
        if (tokenAccount.keyType !== KeetaNet.lib.Account.AccountKeyAlgorithm.TOKEN) {
          const error = new Error('Provided token address is not a valid token identifier');
          error.status = 400;
          throw error;
        }
        tokenForTransfer = tokenAccount;
      } catch (err) {
        const error = new Error('Token address is invalid');
        error.status = 400;
        throw error;
      }
    }

    // Send tokens - matching the working example pattern
    builder.send(recipientAccount, sendAmount, tokenForTransfer);

    // Compute builder blocks (optional but recommended) - matching sample pattern
    const computed = await client.computeBuilderBlocks(builder);

    // Publish to network - matching sample pattern
    const publishResult = await client.publishBuilder(builder);

    // Extract token public key for response
    const tokenPublicKey = tokenForTransfer.publicKeyString?.toString?.()
      || tokenForTransfer.publicKeyString?.get?.()
      || null;

    // Serialize the response to convert any BigInt values to strings
    const response = {
      recipient: recipientAccount.publicKeyString?.toString?.() || recipient.trim(),
      amount: sendAmount.toString(),
      tokenAddress: tokenPublicKey,
      blocks: computed?.blocks || [],
      publish: publishResult,
    };

    // Recursively serialize all BigInt values to strings for JSON compatibility
    return serializeBigInt(response);
  } catch (error) {
    const normalized = normalizeTransferError(error);
    logger.error({ error }, 'Error transferring tokens');

    const httpError = new Error(normalized.message);
    httpError.status = normalized.status;
    httpError.code = normalized.code;
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
  createToken,
  transferTokens,
};

