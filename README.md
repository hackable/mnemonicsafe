# MnemonicSafe

[![CI](https://github.com/hackable/mnemonicsafe/actions/workflows/ci.yml/badge.svg)](https://github.com/hackable/mnemonicsafe/actions/workflows/ci.yml)

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

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/your-username/mnemonicsafe.git
   cd mnemonicsafe

## Installation

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/hackable/mnemonicsafe.git
   cd mnemonicsafe

	2.	Install Dependencies:
Make sure you have Node.js (version 14 or higher) installed, then run:

npm install



Usage

Splitting a Mnemonic into Encrypted Shares

In the example.js file, a sample BIP-39 mnemonic is defined, along with a configuration for splitting the mnemonic into shares:
	•	Mnemonic:
legal winner thank year wave sausage worth useful legal winner thank yellow
	•	Configuration:
	•	Total Shares: 5
	•	Threshold: 3
	•	Passwords: Unique password for each share (e.g., “password1!”, “password2@”, etc.)

The process involves:
	1.	Converting the mnemonic into entropy.
	2.	Splitting the entropy into 5 shares using SSS.
	3.	Encrypting each share with its corresponding password using AES-256-GCM.

Reconstructing the Mnemonic

The reconstruction process:
	1.	Selects a threshold number of encrypted shares.
	2.	Decrypts them using the corresponding passwords.
	3.	Reassembles the original mnemonic using Shamir’s Secret Sharing.

Running the Example

To run the example and see the complete process:

node example.js

The console output will display:
	•	The original BIP-39 mnemonic.
	•	The generated encrypted shares.
	•	The reconstructed mnemonic, confirming the process.

Code Overview
	•	slip39.js
Contains all the core functions:
	•	bip39ToEntropy: Converts a BIP-39 mnemonic to entropy.
	•	splitSecret: Splits the entropy into multiple shares using SSS.
	•	shareToBase64 / base64ToShare: Converts shares to/from Base64.
	•	encryptShare / decryptShare: Encrypts and decrypts shares using AES-256-GCM.
	•	bip39ToSlip39: Main function to create encrypted shares from a mnemonic.
	•	reconstructBip39Mnemonic: Reconstructs the mnemonic from decrypted shares.
	•	example.js
Demonstrates how to use the above functions to split a mnemonic and then reconstruct it.

Security Considerations
	•	Password Management:
Ensure that each share is encrypted with a strong, unique password.
	•	Secure Storage:
Store the encrypted shares and associated passwords in secure locations. Do not store them together.
	•	Encryption Practices:
AES-256-GCM is used with random salts and IVs, and keys are derived via PBKDF2 to provide robust security.
	•	Testing & Auditing:
This code is intended for research and educational purposes. A production system should undergo extensive security reviews and audits.

Future Enhancements
	•	Expiration Metadata:
Future versions may embed an expiration timestamp in each share to disable its use after a certain time.
	•	Threshold Encryption:
Explore replacing per-share passwords with a threshold encryption scheme for further simplifying key management.
	•	HSM Integration:
Consider integration with hardware security modules (HSMs) to enhance key management and storage security.

Conclusion

MnemonicSafe provides a practical approach to secure mnemonic backups by splitting and encrypting a BIP-39 mnemonic into multiple shares. While inspired by SLIP-39, it is not an official implementation but rather an experimental and educational tool. Use MnemonicSafe to understand the principles of secret sharing, encryption, and secure backup design.

License

This project is licensed under the MIT License.

References
	•	Shamir, A. (1979). “How to share a secret.” Communications of the ACM, 22(11), 612-613.
	•	Nakamoto, S. (2008). “Bitcoin: A Peer-to-Peer Electronic Cash System.”
	•	NIST Special Publication 800-38D (AES-GCM recommendations).

---
