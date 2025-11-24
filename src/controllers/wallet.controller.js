const walletService = require('../services/wallet.service');

/**
 * Create a new wallet using KeetaNet SDK with BIP39 mnemonic
 */
const createWallet = (req, res, next) => {
  try {
    const wallet = walletService.createWallet();
    
    res.status(201).json({
      success: true,
      data: {
        address: wallet.address,
        publicKey: wallet.publicKey,
        mnemonic: wallet.mnemonic, // BIP39 mnemonic phrase (12 words)
        seed: wallet.seed, // Hex seed derived from mnemonic (for backward compatibility)
        // Note: Both mnemonic and seed are sensitive and should be encrypted before storage
        // In production, consider encrypting before sending
      },
      message: 'Wallet created successfully',
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Import wallet from seed (KeetaNet primary method)
 */
const importWalletFromSeed = (req, res, next) => {
  try {
    const { seed } = req.body;

    if (!seed) {
      return res.status(400).json({
        success: false,
        message: 'Seed is required',
      });
    }

    const wallet = walletService.importWalletFromSeed(seed);
    
    res.status(200).json({
      success: true,
      data: {
        address: wallet.address,
        publicKey: wallet.publicKey,
      },
      message: 'Wallet imported successfully',
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Import wallet from mnemonic (for backward compatibility)
 */
const importWalletFromMnemonic = (req, res, next) => {
  try {
    const { mnemonic } = req.body;

    if (!mnemonic) {
      return res.status(400).json({
        success: false,
        message: 'Mnemonic phrase is required',
      });
    }

    const wallet = walletService.importWalletFromMnemonic(mnemonic);
    
    res.status(200).json({
      success: true,
      data: {
        address: wallet.address,
        publicKey: wallet.publicKey,
      },
      message: 'Wallet imported successfully',
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Import wallet from private key (treated as seed in KeetaNet)
 */
const importWalletFromPrivateKey = (req, res, next) => {
  try {
    const { privateKey } = req.body;

    if (!privateKey) {
      return res.status(400).json({
        success: false,
        message: 'Private key is required',
      });
    }

    const wallet = walletService.importWalletFromPrivateKey(privateKey);
    
    res.status(200).json({
      success: true,
      data: {
        address: wallet.address,
        publicKey: wallet.publicKey,
      },
      message: 'Wallet imported successfully',
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Encrypt wallet data
 */
const encryptWallet = (req, res, next) => {
  try {
    const { data, password } = req.body;

    if (!data || !password) {
      return res.status(400).json({
        success: false,
        message: 'Data and password are required',
      });
    }

    const encrypted = walletService.encryptWalletData(data, password);
    
    res.status(200).json({
      success: true,
      data: encrypted,
      message: 'Wallet data encrypted successfully',
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Decrypt wallet data
 */
const decryptWallet = (req, res, next) => {
  try {
    const { encryptedData, password } = req.body;

    if (!encryptedData || !password) {
      return res.status(400).json({
        success: false,
        message: 'Encrypted data and password are required',
      });
    }

    const decrypted = walletService.decryptWalletData(encryptedData, password);
    
    res.status(200).json({
      success: true,
      data: { decrypted },
      message: 'Wallet data decrypted successfully',
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get account balance and tokens
 */
const getAccountBalance = async (req, res, next) => {
  try {
    const { address } = req.params;

    if (!address) {
      return res.status(400).json({
        success: false,
        message: 'Address is required',
      });
    }

    const accountData = await walletService.getAccountBalance(address);
    
    res.status(200).json({
      success: true,
      data: accountData,
      message: 'Account balance retrieved successfully',
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get account info
 */
const getAccountInfo = async (req, res, next) => {
  try {
    const { address } = req.params;

    if (!address) {
      return res.status(400).json({
        success: false,
        message: 'Address is required',
      });
    }

    const accountInfo = await walletService.getAccountInfo(address);
    
    res.status(200).json({
      success: true,
      data: accountInfo,
      message: 'Account info retrieved successfully',
    });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  createWallet,
  importWalletFromSeed,
  importWalletFromMnemonic,
  importWalletFromPrivateKey,
  encryptWallet,
  decryptWallet,
  getAccountBalance,
  getAccountInfo,
};

