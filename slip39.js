// slip39.js
const bip39 = require("bip39");
const crypto = require("crypto");
const sss = require("shamirs-secret-sharing");

/**
 * Converts a BIP-39 mnemonic phrase to entropy.
 * @param {string} bip39Mnemonic - A valid BIP-39 mnemonic phrase.
 * @returns {Buffer} - Entropy derived from the BIP-39 mnemonic.
 * @throws Will throw an error if the mnemonic is invalid.
 */
function bip39ToEntropy(bip39Mnemonic) {
  if (!bip39.validateMnemonic(bip39Mnemonic)) {
    throw new Error("Invalid BIP-39 mnemonic");
  }
  const entropyHex = bip39.mnemonicToEntropy(bip39Mnemonic);
  return Buffer.from(entropyHex, "hex");
}

/**
 * Converts entropy to a BIP-39 mnemonic phrase.
 * @param {Buffer} entropy - Entropy to convert.
 * @returns {string} - BIP-39 mnemonic.
 */
function entropyToBip39(entropy) {
  return bip39.entropyToMnemonic(entropy.toString("hex"));
}

/**
 * Splits the secret entropy into shares using Shamir's Secret Sharing.
 * @param {Buffer} secret - The secret entropy to split.
 * @param {number} totalShares - The total number of shares to generate.
 * @param {number} threshold - The minimum number of shares needed to reconstruct the secret.
 * @returns {Array<Buffer>} - Array of binary shares.
 */
function splitSecret(secret, totalShares, threshold) {
  if (threshold > totalShares) {
    throw new Error("Threshold cannot be greater than total shares");
  }
  // Convert secret to a Uint8Array as required by shamirs-secret-sharing
  const shares = sss.split(secret, { shares: totalShares, threshold: threshold });
  return shares;
}

/**
 * Converts a binary share into a Base64-encoded string.
 * @param {Buffer} share - A single SSS share.
 * @returns {string} - Base64-encoded string representing the share.
 */
function shareToBase64(share) {
  return share.toString("base64");
}

/**
 * Converts a Base64-encoded share back to a Buffer.
 * @param {string} base64Share - The Base64-encoded share.
 * @returns {Buffer} - The original binary share.
 * @throws Will throw an error if the Base64 string is invalid.
 */
function base64ToShare(base64Share) {
  return Buffer.from(base64Share, "base64");
}

/**
 * Encrypts a Base64-encoded share with a password using AES-256-GCM.
 * @param {string} base64Share - The Base64-encoded share to encrypt.
 * @param {string} password - The password to use for encryption.
 * @returns {string} - Encrypted share in Base64 format, including salt, IV, and auth tag.
 */
function encryptShare(base64Share, password) {
  // Derive a key using PBKDF2 with a random salt
  const salt = crypto.randomBytes(16);
  const key = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');

  // Encrypt using AES-256-GCM
  const iv = crypto.randomBytes(12); // 96-bit nonce for GCM
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(base64Share, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();

  // Combine salt, iv, authTag, and encrypted data
  const encryptedData = Buffer.concat([salt, iv, authTag, encrypted]);

  return encryptedData.toString("base64");
}

/**
 * Decrypts an encrypted share with a password.
 * @param {string} encryptedShare - The encrypted share in Base64 format.
 * @param {string} password - The password to decrypt with.
 * @returns {string} - Decrypted Base64-encoded share.
 * @throws Will throw an error if decryption fails.
 */
function decryptShare(encryptedShare, password) {
  const encryptedBuffer = Buffer.from(encryptedShare, "base64");

  // Extract salt, iv, authTag, and encrypted data
  const salt = encryptedBuffer.slice(0, 16);
  const iv = encryptedBuffer.slice(16, 28);
  const authTag = encryptedBuffer.slice(28, 44);
  const encryptedData = encryptedBuffer.slice(44);

  // Derive the key using PBKDF2 with the extracted salt
  const key = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');

  // Decrypt using AES-256-GCM
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(authTag);
  let decrypted;
  try {
    decrypted = Buffer.concat([decipher.update(encryptedData), decipher.final()]);
  } catch (err) {
    throw new Error("Failed to decrypt share. Possible incorrect password or corrupted data.");
  }

  return decrypted.toString("utf8"); // This is the Base64-encoded share
}

/**
 * Converts multiple binary shares to Base64-encoded strings.
 * @param {Array<Buffer>} shares - Array of binary shares.
 * @returns {Array<string>} - Array of Base64-encoded strings.
 */
function sharesToBase64(shares) {
  return shares.map((share) => shareToBase64(share));
}

/**
 * Converts multiple Base64-encoded shares back to binary shares.
 * @param {Array<string>} base64Shares - Array of Base64-encoded shares.
 * @returns {Array<Buffer>} - Array of binary shares.
 */
function base64ToShares(base64Shares) {
  return base64Shares.map((base64Share) => base64ToShare(base64Share));
}

/**
 * Encrypts multiple Base64-encoded shares with their respective passwords.
 * @param {Array<string>} base64Shares - Array of Base64-encoded shares.
 * @param {Array<string>} passwords - Array of passwords for each share.
 * @returns {Array<string>} - Array of encrypted shares in Base64 format.
 */
function encryptShares(base64Shares, passwords) {
  return base64Shares.map((base64Share, index) => encryptShare(base64Share, passwords[index]));
}

/**
 * Decrypts multiple encrypted shares with their respective passwords.
 * @param {Array<string>} encryptedShares - Array of encrypted shares in Base64 format.
 * @param {Array<string>} passwords - Array of passwords for each share.
 * @returns {Array<string>} - Array of decrypted Base64-encoded shares.
 */
function decryptShares(encryptedShares, passwords) {
  return encryptedShares.map((encryptedShare, index) => decryptShare(encryptedShare, passwords[index]));
}

/**
 * Converts a BIP-39 mnemonic to SLIP-39 shares with password encryption.
 * @param {string} bip39Mnemonic - The BIP-39 mnemonic to convert.
 * @param {number} totalShares - Total number of shares to generate.
 * @param {number} threshold - Minimum number of shares required to reconstruct.
 * @param {Array<string>} passwords - Array of passwords for each share.
 * @returns {Array<string>} - Array of encrypted shares in Base64 format.
 */
function bip39ToSlip39(bip39Mnemonic, totalShares, threshold, passwords) {
  if (passwords.length !== totalShares) {
    throw new Error("Number of passwords must match the total number of shares");
  }

  const entropy = bip39ToEntropy(bip39Mnemonic);

  // Split the entropy into shares
  const shares = splitSecret(entropy, totalShares, threshold);

  // Convert shares to Base64
  const base64Shares = sharesToBase64(shares);

  // Encrypt each share with its corresponding password
  const encryptedShares = encryptShares(base64Shares, passwords);

  return encryptedShares;
}

/**
 * Reconstructs the BIP-39 mnemonic from decrypted SLIP-39 shares.
 * @param {Array<string>} decryptedShares - Array of decrypted Base64-encoded shares.
 * @returns {string} - The original BIP-39 mnemonic.
 */
function reconstructBip39Mnemonic(decryptedShares) {
  if (decryptedShares.length === 0) {
    throw new Error("No shares provided for reconstruction.");
  }

  // Convert Base64 shares back to binary
  const shares = base64ToShares(decryptedShares);

  // Use Shamir's Secret Sharing to combine the shares
  let reconstructedEntropy;
  try {
    reconstructedEntropy = sss.combine(shares);
  } catch (err) {
    throw new Error("Failed to reconstruct entropy from shares. Ensure you have enough valid shares.");
  }

  // Convert entropy back to BIP-39 mnemonic
  return entropyToBip39(reconstructedEntropy);
}

module.exports = {
  bip39ToSlip39,
  decryptShare, // For decrypting individual shares if needed
  decryptShares, // For decrypting multiple shares
  reconstructBip39Mnemonic,
  encryptShare, // Exported for potential separate use
  encryptShares, // Exported for encrypting multiple shares
};
