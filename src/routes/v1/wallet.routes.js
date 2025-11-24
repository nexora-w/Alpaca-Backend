const express = require('express');
const walletController = require('../../controllers/wallet.controller');

const router = express.Router();

router.post('/create', walletController.createWallet);
router.post('/import/seed', walletController.importWalletFromSeed);
router.post('/import/mnemonic', walletController.importWalletFromMnemonic);
router.post('/import/private-key', walletController.importWalletFromPrivateKey);
router.post('/encrypt', walletController.encryptWallet);
router.post('/decrypt', walletController.decryptWallet);
router.get('/balance/:address', walletController.getAccountBalance);
router.get('/info/:address', walletController.getAccountInfo);
router.get('/pools', walletController.getPools);

module.exports = router;

