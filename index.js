// slip39.js
const bip39 = require("bip39");
const crypto = require("crypto");
const sss = require("shamirs-secret-sharing");

// Use crypto polyfill packages
if (typeof window !== 'undefined' && !window.crypto) {
  window.crypto = require('crypto-browserify');
}

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
 * Generates a secure secret identifier for integrity checking.
 * @param {Buffer} secret - The original secret.
 * @returns {Buffer} - 32-byte secret identifier.
 */
function generateSecretId(secret) {
  // Generate a deterministic but unique identifier for this secret
  return crypto.createHash('sha256').update(secret).update('SECRET_ID_SALT_2024').digest();
}

/**
 * Creates an integrity checksum for a share.
 * @param {Buffer} share - The raw share data.
 * @param {Buffer} secretId - The secret identifier.
 * @param {number} shareIndex - The index of this share.
 * @returns {Buffer} - 32-byte HMAC checksum.
 */
function createShareChecksum(share, secretId, shareIndex) {
  const hmac = crypto.createHmac('sha256', secretId);
  hmac.update(share);
  hmac.update(Buffer.from([shareIndex])); // Include share index
  hmac.update('SHARE_INTEGRITY_2024'); // Additional salt
  return hmac.digest();
}

/**
 * Browser-compatible timing-safe comparison function.
 * @param {Buffer} a - First buffer to compare.
 * @param {Buffer} b - Second buffer to compare.
 * @returns {boolean} - True if buffers are equal.
 */
function timingSafeEqual(a, b) {
  if (crypto.timingSafeEqual) {
    return crypto.timingSafeEqual(a, b);
  }
  
  // Browser fallback - constant time comparison
  if (a.length !== b.length) {
    return false;
  }
  
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }
  return result === 0;
}

/**
 * Verifies the integrity of a share.
 * @param {Buffer} share - The raw share data.
 * @param {Buffer} secretId - The expected secret identifier.
 * @param {number} shareIndex - The index of this share.
 * @param {Buffer} expectedChecksum - The expected checksum.
 * @returns {boolean} - True if share is valid and untampered.
 */
function verifyShareIntegrity(share, secretId, shareIndex, expectedChecksum) {
  const computedChecksum = createShareChecksum(share, secretId, shareIndex);
  return timingSafeEqual(computedChecksum, expectedChecksum);
}

/**
 * Securely splits the secret entropy into shares with integrity protection.
 * @param {Buffer} secret - The secret entropy to split.
 * @param {number} totalShares - The total number of shares to generate.
 * @param {number} threshold - The minimum number of shares needed to reconstruct the secret.
 * @returns {Array<Buffer>} - Array of secure binary shares with integrity data.
 */
function splitSecret(secret, totalShares, threshold) {
  if (threshold > totalShares) {
    throw new Error("Threshold cannot be greater than total shares");
  }
  
  // Generate a unique secret identifier
  const secretId = generateSecretId(secret);
  
  // Use the underlying SSS library to split the secret
  const rawShares = sss.split(secret, { shares: totalShares, threshold: threshold });
  
  // Create secure shares with integrity protection
  const secureShares = rawShares.map((rawShare, index) => {
    // Convert rawShare to Buffer if it isn't already
    const rawShareBuffer = Buffer.isBuffer(rawShare) ? rawShare : Buffer.from(rawShare);
    
    // Create integrity checksum for this share
    const checksum = createShareChecksum(rawShareBuffer, secretId, index);
    
    // Create secure share format:
    // [1 byte: version] [32 bytes: secretId] [32 bytes: checksum] [1 byte: shareIndex] [variable: rawShare]
    const secureShare = Buffer.alloc(1 + 32 + 32 + 1 + rawShareBuffer.length);
    let offset = 0;
    
    secureShare[offset] = 0x01; // Version 1
    offset += 1;
    
    secretId.copy(secureShare, offset);
    offset += 32;
    
    checksum.copy(secureShare, offset);
    offset += 32;
    
    secureShare[offset] = index; // Share index
    offset += 1;
    
    rawShareBuffer.copy(secureShare, offset);
    
    return secureShare;
  });
  
  return secureShares;
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
  // Derive a key using PBKDF2 with a cryptographically secure random salt
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
 * Parses a secure share and extracts its components.
 * @param {Buffer} secureShare - The secure share buffer.
 * @returns {Object} - Object containing share components.
 */
function parseSecureShare(secureShare) {
  // Minimum length: 1 + 32 + 32 + 1 + min_share_size
  if (secureShare.length < 66) {
    throw new Error("Share too short: invalid secure share format");
  }
  
  let offset = 0;
  
  // Parse version
  const version = secureShare[offset];
  offset += 1;
  
  if (version !== 0x01) {
    throw new Error(`Unsupported share version: ${version}`);
  }
  
  // Parse secret ID
  const secretId = secureShare.slice(offset, offset + 32);
  offset += 32;
  
  // Parse checksum
  const checksum = secureShare.slice(offset, offset + 32);
  offset += 32;
  
  // Parse share index
  const shareIndex = secureShare[offset];
  offset += 1;
  
  // Parse raw share data
  const rawShare = secureShare.slice(offset);
  
  return {
    version,
    secretId,
    checksum,
    shareIndex,
    rawShare
  };
}

/**
 * Reconstructs the BIP-39 mnemonic from decrypted secure SLIP-39 shares.
 * @param {Array<string>} decryptedShares - Array of decrypted Base64-encoded secure shares.
 * @param {number} expectedThreshold - The minimum number of shares required (optional, for validation).
 * @returns {string} - The original BIP-39 mnemonic.
 */
function reconstructBip39Mnemonic(decryptedShares, expectedThreshold = null) {
  if (decryptedShares.length === 0) {
    throw new Error("No shares provided for reconstruction.");
  }

  // Validate minimum threshold if provided
  if (expectedThreshold !== null && decryptedShares.length < expectedThreshold) {
    throw new Error(`Insufficient shares provided. Need at least ${expectedThreshold}, got ${decryptedShares.length}.`);
  }

  // Parse and validate all shares
  const parsedShares = [];
  let commonSecretId = null;
  
  for (let i = 0; i < decryptedShares.length; i++) {
    const shareString = decryptedShares[i];
    
    // Validate base64 format
    if (typeof shareString !== 'string' || shareString.length === 0) {
      throw new Error(`Invalid share format at index ${i}: not a valid string`);
    }
    
    let secureShareBuffer;
    try {
      secureShareBuffer = Buffer.from(shareString, 'base64');
    } catch (err) {
      throw new Error(`Invalid share at index ${i}: not valid base64 data`);
    }
    
    // Parse the secure share
    let parsed;
    try {
      parsed = parseSecureShare(secureShareBuffer);
    } catch (err) {
      throw new Error(`Invalid share at index ${i}: ${err.message}`);
    }
    
    // Verify all shares belong to the same secret
    if (commonSecretId === null) {
      commonSecretId = parsed.secretId;
    } else if (!commonSecretId.equals(parsed.secretId)) {
      throw new Error(`Share ${i} belongs to a different secret. Cannot mix shares from different secrets.`);
    }
    
    // Verify share integrity
    if (!verifyShareIntegrity(parsed.rawShare, parsed.secretId, parsed.shareIndex, parsed.checksum)) {
      throw new Error(`Share ${i} failed integrity check. Share may be corrupted or tampered with.`);
    }
    
    parsedShares.push(parsed);
  }
  
  // Check for duplicate share indices
  const shareIndices = parsedShares.map(s => s.shareIndex);
  const uniqueIndices = new Set(shareIndices);
  if (uniqueIndices.size !== shareIndices.length) {
    throw new Error("Duplicate share indices detected. Cannot use the same share multiple times.");
  }
  
  // Extract raw shares for reconstruction
  const rawShares = parsedShares.map(s => {
    // Ensure the raw share is in the correct format for the SSS library
    return Buffer.isBuffer(s.rawShare) ? s.rawShare : Buffer.from(s.rawShare);
  });
  
  // Use Shamir's Secret Sharing to combine the shares
  let reconstructedEntropy;
  try {
    reconstructedEntropy = sss.combine(rawShares);
  } catch (err) {
    throw new Error("Failed to reconstruct entropy from shares. Ensure you have enough valid shares from the same secret.");
  }

  // Validate reconstructed entropy
  if (!reconstructedEntropy || reconstructedEntropy.length === 0) {
    throw new Error("Reconstruction failed: No entropy recovered.");
  }

  // Validate entropy length (should be 16, 20, 24, 28, or 32 bytes for valid BIP39)
  const validLengths = [16, 20, 24, 28, 32];
  if (!validLengths.includes(reconstructedEntropy.length)) {
    throw new Error(`Reconstruction failed: Invalid entropy length ${reconstructedEntropy.length}. Expected one of: ${validLengths.join(', ')}`);
  }

  // Verify the reconstructed secret matches the expected secret ID
  const expectedSecretId = generateSecretId(reconstructedEntropy);
  if (!expectedSecretId.equals(commonSecretId)) {
    throw new Error("Reconstruction failed: Secret ID mismatch. Shares may be corrupted or from different secrets.");
  }

  // Convert entropy back to BIP-39 mnemonic
  let mnemonic;
  try {
    mnemonic = entropyToBip39(reconstructedEntropy);
  } catch (err) {
    throw new Error("Reconstruction failed: Cannot convert entropy to valid mnemonic");
  }
  
  // Final validation that the reconstructed mnemonic is valid
  if (!bip39.validateMnemonic(mnemonic)) {
    throw new Error("Reconstruction failed: Invalid mnemonic recovered.");
  }

  return mnemonic;
}

module.exports = {
  bip39ToSlip39,
  decryptShare, // For decrypting individual shares if needed
  decryptShares, // For decrypting multiple shares
  reconstructBip39Mnemonic,
  encryptShare, // Exported for potential separate use
  encryptShares, // Exported for encrypting multiple shares
};
