// example.js
const {
  bip39ToSlip39,
  decryptShares,
  reconstructBip39Mnemonic,
} = require("./index");

// Example BIP-39 mnemonic (for demonstration purposes only)
// **WARNING:** Never expose real mnemonics. Use this only for testing.
const originalMnemonic = "legal winner thank year wave sausage worth useful legal winner thank yellow";

// Configuration
const totalShares = 5;
const threshold = 3;

// Passwords for each share (ensure these are strong and kept secure)
const passwords = [
  "password1!",
  "password2@",
  "password3#",
  "password4$",
  "password5%",
];

try {
  console.log("Original BIP-39 Mnemonic:");
  console.log(originalMnemonic);
  console.log("\nSplitting mnemonic into shares...");

  // Split the mnemonic into encrypted shares
  const encryptedShares = bip39ToSlip39(originalMnemonic, totalShares, threshold, passwords);

  // Display the encrypted shares
  console.log("\nEncrypted Shares:");
  encryptedShares.forEach((share, index) => {
    console.log(`Share ${index + 1}: ${share}`);
  });

  // Simulate selecting threshold number of shares to reconstruct
  // In a real scenario, you would collect these from secure storage
  const selectedShareIndices = [0, 2, 4]; // Selecting shares 1, 3, and 5
  const selectedEncryptedShares = selectedShareIndices.map(index => encryptedShares[index]);

  // Passwords corresponding to the selected shares
  const selectedPasswords = selectedShareIndices.map(index => passwords[index]);

  // Decrypt the selected shares
  const decryptedShares = decryptShares(selectedEncryptedShares, selectedPasswords);

  // Reconstruct the original mnemonic
  const reconstructedMnemonic = reconstructBip39Mnemonic(decryptedShares);

  console.log("\nReconstructed BIP-39 Mnemonic:");
  console.log(reconstructedMnemonic);

  // Verify that the reconstructed mnemonic matches the original
  if (reconstructedMnemonic === originalMnemonic) {
    console.log("\nSuccess: The reconstructed mnemonic matches the original.");
  } else {
    console.log("\nError: The reconstructed mnemonic does not match the original.");
  }
} catch (err) {
  console.error(`Error: ${err.message}`);
}
