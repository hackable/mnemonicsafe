// test/test.js
const { expect } = require('chai');
const { bip39ToSlip39, decryptShares, reconstructBip39Mnemonic } = require('..');

// Example BIP-39 mnemonic (for testing purposes only)
const originalMnemonic = "legal winner thank year wave sausage worth useful legal winner thank yellow";
const totalShares = 5;
const threshold = 3;
const passwords = [
  "password1!",
  "password2@",
  "password3#",
  "password4$",
  "password5%"
];

describe('MnemonicSafe (SLIP-39 Inspired) Tests', () => {
  let encryptedShares;

  before(() => {
    // Generate encrypted shares from the original mnemonic
    encryptedShares = bip39ToSlip39(originalMnemonic, totalShares, threshold, passwords);
  });

  it('should generate the correct number of encrypted shares', () => {
    expect(encryptedShares).to.be.an('array');
    expect(encryptedShares).to.have.lengthOf(totalShares);
  });

  it('should reconstruct the mnemonic when provided with a threshold number of valid shares', () => {
    // For testing, select shares at indices 0, 2, and 4 (i.e. 3 shares)
    const selectedIndices = [0, 2, 4];
    const selectedEncryptedShares = selectedIndices.map(i => encryptedShares[i]);
    const selectedPasswords = selectedIndices.map(i => passwords[i]);

    // Decrypt the selected shares
    const decryptedShares = decryptShares(selectedEncryptedShares, selectedPasswords);

    // Reconstruct the mnemonic
    const reconstructedMnemonic = reconstructBip39Mnemonic(decryptedShares);

    expect(reconstructedMnemonic).to.equal(originalMnemonic);
  });

  it('should throw an error when decryption is attempted with an incorrect password', () => {
    // Change one of the passwords to an incorrect value
    const wrongPasswords = [...passwords];
    wrongPasswords[0] = "wrongpassword";

    const selectedIndices = [0, 2, 4];
    const selectedEncryptedShares = selectedIndices.map(i => encryptedShares[i]);
    const selectedPasswords = selectedIndices.map(i => wrongPasswords[i]);

    // Expect an error during decryption or reconstruction
    expect(() => {
      const decryptedShares = decryptShares(selectedEncryptedShares, selectedPasswords);
      reconstructBip39Mnemonic(decryptedShares);
    }).to.throw();
  });
});