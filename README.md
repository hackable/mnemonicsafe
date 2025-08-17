# MnemonicSafe

![Node.js CI](https://github.com/hackable/mnemonicsafe/workflows/Node.js%20CI/badge.svg)
[![npm version](https://badge.fury.io/js/mnemonicsafe.svg)](https://badge.fury.io/js/mnemonicsafe)
[![npm downloads](https://img.shields.io/npm/dm/mnemonicsafe.svg)](https://www.npmjs.com/package/mnemonicsafe)

MnemonicSafe is a secure backup solution for cryptocurrency mnemonics. Inspired by the ideas behind SLIP-39, MnemonicSafe splits a BIP-39 mnemonic into multiple shares using Shamir's Secret Sharing (SSS) and then encrypts each share using AES-256-GCM with unique passwords. This approach requires a threshold number of shares to reconstruct the original mnemonic, thereby enhancing security and resilience against loss or compromise.

> **Disclaimer:**  
> MnemonicSafe is an educational and experimental project and is not an official implementation of SLIP-39 by SatoshiLabs. Use this code for testing and research purposes only, and never expose real mnemonics without a thorough security review.

## Overview

MnemonicSafe works by:

1. **Converting the mnemonic into entropy:**  
   The provided BIP-39 mnemonic is validated and converted into its underlying binary entropy.

2. **Splitting the entropy using Shamir's Secret Sharing (SSS):**  
   The entropy is divided into multiple shares such that only a configurable threshold of shares is required to reconstruct the original secret.

3. **Encrypting each share:**  
   Each share is converted into a Base64 string and then encrypted using AES-256-GCM. A unique password is used for each share, and robust key derivation (using PBKDF2 with a random salt) ensures strong encryption.

4. **Reconstructing the mnemonic:**  
   By decrypting a threshold number of shares with their corresponding passwords and combining them via SSS, the original mnemonic is recovered.

While our code is sometimes called "SLIP-39" in this repository, note that SLIP-39 is a standard developed by SatoshiLabs. MnemonicSafe is inspired by these ideas but does not adhere to the official SLIP-39 specification.

## Features

- **BIP-39 Mnemonic Conversion:** Validates and converts mnemonics to entropy.
- **Secret Splitting with SSS:** Splits the mnemonic's entropy into multiple shares.
- **AES-256-GCM Encryption:** Encrypts each share with its own password using PBKDF2 key derivation, random salt, and IV.
- **Share Reconstruction:** Combines a threshold number of decrypted shares to recover the original mnemonic.
- **Extensible Design:** Ready for future enhancements like expiration metadata or threshold encryption.

## Installation

### Option 1: Install from npm (Recommended)

```bash
npm install mnemonicsafe
```

### Option 2: Clone from Source

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/hackable/mnemonicsafe.git
   cd mnemonicsafe
   ```

2. **Install Dependencies:**

   Make sure you have Node.js installed, then run:
   ```bash
   npm install
   ```


## Usage

### Basic Usage (npm package)

```javascript
const MnemonicSafe = require('mnemonicsafe');

// Your BIP-39 mnemonic
const mnemonic = 'legal winner thank year wave sausage worth useful legal winner thank yellow';

// Configuration
const totalShares = 5;
const threshold = 3;
const passwords = ['password1!', 'password2@', 'password3#', 'password4$', 'password5%'];

// Split the mnemonic into encrypted shares
const encryptedShares = MnemonicSafe.splitMnemonic(mnemonic, totalShares, threshold, passwords);
console.log('Encrypted shares:', encryptedShares);

// Reconstruct the mnemonic using threshold number of shares
const selectedShares = encryptedShares.slice(0, threshold);
const selectedPasswords = passwords.slice(0, threshold);
const reconstructed = MnemonicSafe.reconstructMnemonic(selectedShares, selectedPasswords);
console.log('Reconstructed mnemonic:', reconstructed);
```

### Browser Usage

The package is also available for browser environments. You can include it in your HTML:

```html
<script src="node_modules/mnemonicsafe/dist/index.js"></script>
<script>
  // MnemonicSafe is now available as a global variable
  const mnemonic = 'legal winner thank year wave sausage worth useful legal winner thank yellow';
  const encryptedShares = MnemonicSafe.splitMnemonic(mnemonic, 5, 3, ['pass1', 'pass2', 'pass3', 'pass4', 'pass5']);
  console.log('Encrypted shares:', encryptedShares);
</script>
```

Or using a module bundler like webpack or browserify:

```javascript
import MnemonicSafe from 'mnemonicsafe';
// or
const MnemonicSafe = require('mnemonicsafe');
```

### Development Usage (cloned repository)

### Splitting a Mnemonic into Encrypted Shares

In the `example.js` file, a sample BIP-39 mnemonic is defined along with a configuration for splitting the mnemonic into shares:

- **Mnemonic:**  
  `legal winner thank year wave sausage worth useful legal winner thank yellow`

- **Configuration:**
  - **Total Shares:** 5
  - **Threshold:** 3
  - **Passwords:** Unique password for each share (e.g., `password1!`, `password2@`, etc.)

## The Process Involves:

1. Converting the mnemonic into entropy.
2. Splitting the entropy into 5 shares using Shamir's Secret Sharing (SSS).
3. Encrypting each share with its corresponding password using AES-256-GCM.

### Reconstructing the Mnemonic

The reconstruction process:

1. Selects a threshold number of encrypted shares.
2. Decrypts them using the corresponding passwords.
3. Reassembles the original mnemonic using Shamir’s Secret Sharing.

### Running the Example

To run the example and see the complete process:

```bash
node example.js
```
