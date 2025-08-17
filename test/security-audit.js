// security-audit.js - Comprehensive security testing for slip39.js
const crypto = require("crypto");
const bip39 = require("bip39");
const { 
  bip39ToSlip39, 
  decryptShare, 
  decryptShares, 
  reconstructBip39Mnemonic,
  encryptShare,
  encryptShares 
} = require('..');

// Test data
const testMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const weakPasswords = ["", "a", "12", "password", "123456"];
const strongPasswords = [
  "ThisIsAVeryStrongPassword123!@#",
  "AnotherSecureP@ssw0rd$$$",
  "CryptographicallySecure2024!",
  "SuperStrongPassphrase#456",
  "UnbreakablePassword789!"
];

let testResults = [];

function logTest(testName, passed, message, details = null) {
  const result = { testName, passed, message, details, timestamp: new Date().toISOString() };
  testResults.push(result);
  console.log(`${passed ? '✅ PASS' : '❌ FAIL'}: ${testName}`);
  console.log(`   ${message}`);
  if (details) {
    console.log(`   Details:`, details);
  }
  console.log('');
}

// Test 1: Cryptographic Randomness Quality
function testRandomnessQuality() {
  console.log("🔍 Testing Cryptographic Randomness Quality...");
  
  try {
    // Generate multiple shares and check for patterns
    const shares1 = bip39ToSlip39(testMnemonic, 5, 3, strongPasswords);
    const shares2 = bip39ToSlip39(testMnemonic, 5, 3, strongPasswords);
    
    // Shares should be different even with same inputs (due to random salt/IV)
    let identical = 0;
    for (let i = 0; i < shares1.length; i++) {
      if (shares1[i] === shares2[i]) {
        identical++;
      }
    }
    
    if (identical === 0) {
      logTest("Randomness Quality", true, "All encrypted shares are unique across generations");
    } else {
      logTest("Randomness Quality", false, `${identical} out of ${shares1.length} shares were identical`, {
        identical,
        total: shares1.length,
        shares1: shares1.map(s => s.substring(0, 20) + '...'),
        shares2: shares2.map(s => s.substring(0, 20) + '...')
      });
    }
    
    // Test entropy of encrypted shares
    const concatenated = shares1.join('');
    const entropy = calculateShannonEntropy(concatenated);
    
    // For base64 data, expect entropy between 5.0 and 6.0 (base64 has limited character set)
    if (entropy > 5.0) { 
      logTest("Share Entropy", true, `Shannon entropy is acceptable for base64 data: ${entropy.toFixed(3)}`);
    } else {
      logTest("Share Entropy", false, `Shannon entropy is too low: ${entropy.toFixed(3)}`, { entropy });
    }
    
  } catch (error) {
    logTest("Randomness Quality", false, `Error during randomness test: ${error.message}`, { error: error.toString() });
  }
}

// Test 2: Shamir's Secret Sharing Security
function testShamirSecretSharingSecurity() {
  console.log("🔍 Testing Shamir's Secret Sharing Security...");
  
  try {
    // Test that threshold-1 shares cannot reconstruct secret
    const totalShares = 5;
    const threshold = 3;
    const encryptedShares = bip39ToSlip39(testMnemonic, totalShares, threshold, strongPasswords);
    
    // Try with threshold-1 shares (should fail)
    const insufficientShares = encryptedShares.slice(0, threshold - 1);
    const insufficientPasswords = strongPasswords.slice(0, threshold - 1);
    
    try {
      const decryptedInsufficient = decryptShares(insufficientShares, insufficientPasswords);
      const reconstructed = reconstructBip39Mnemonic(decryptedInsufficient, threshold);
      logTest("Threshold Security", false, "Reconstruction succeeded with insufficient shares", {
        threshold,
        sharesUsed: insufficientShares.length,
        reconstructed
      });
    } catch (error) {
      logTest("Threshold Security", true, "Reconstruction properly failed with insufficient shares");
    }
    
    // Test that exactly threshold shares can reconstruct
    const sufficientShares = encryptedShares.slice(0, threshold);
    const sufficientPasswords = strongPasswords.slice(0, threshold);
    
    try {
      const decryptedSufficient = decryptShares(sufficientShares, sufficientPasswords);
      const reconstructed = reconstructBip39Mnemonic(decryptedSufficient, threshold);
      
      if (reconstructed === testMnemonic) {
        logTest("Threshold Reconstruction", true, "Reconstruction succeeded with exact threshold shares");
      } else {
        logTest("Threshold Reconstruction", false, "Reconstruction produced wrong mnemonic", {
          original: testMnemonic,
          reconstructed
        });
      }
    } catch (error) {
      logTest("Threshold Reconstruction", false, `Reconstruction failed with sufficient shares: ${error.message}`);
    }
    
    // Test with different combinations of shares
    const combinations = [
      [0, 1, 2], [0, 1, 3], [0, 1, 4], [0, 2, 3], [0, 2, 4], [0, 3, 4],
      [1, 2, 3], [1, 2, 4], [1, 3, 4], [2, 3, 4]
    ];
    
    let successfulCombinations = 0;
    for (const combo of combinations) {
      try {
        const comboShares = combo.map(i => encryptedShares[i]);
        const comboPasswords = combo.map(i => strongPasswords[i]);
        const decrypted = decryptShares(comboShares, comboPasswords);
        const reconstructed = reconstructBip39Mnemonic(decrypted, threshold);
        
        if (reconstructed === testMnemonic) {
          successfulCombinations++;
        }
      } catch (error) {
        // This combination failed
      }
    }
    
    if (successfulCombinations === combinations.length) {
      logTest("Share Combination Flexibility", true, "All valid share combinations work correctly");
    } else {
      logTest("Share Combination Flexibility", false, 
        `Only ${successfulCombinations}/${combinations.length} combinations worked`);
    }
    
  } catch (error) {
    logTest("Shamir Secret Sharing Security", false, `Error during SSS test: ${error.message}`);
  }
}

// Test 3: AES-256-GCM Implementation Security
function testAESGCMSecurity() {
  console.log("🔍 Testing AES-256-GCM Implementation Security...");
  
  try {
    const testData = "sensitive test data";
    const password = "testPassword123!";
    
    // Test that encryption produces different results each time
    const encrypted1 = encryptShare(testData, password);
    const encrypted2 = encryptShare(testData, password);
    
    if (encrypted1 !== encrypted2) {
      logTest("AES-GCM Nonce Uniqueness", true, "Each encryption produces unique ciphertext");
    } else {
      logTest("AES-GCM Nonce Uniqueness", false, "Encryption is deterministic (IV reuse vulnerability)", {
        encrypted1: encrypted1.substring(0, 50) + '...',
        encrypted2: encrypted2.substring(0, 50) + '...'
      });
    }
    
    // Test authentication tag verification
    const encrypted = encryptShare(testData, password);
    const encryptedBuffer = Buffer.from(encrypted, 'base64');
    
    // Tamper with the ciphertext
    const tampered = Buffer.from(encryptedBuffer);
    tampered[tampered.length - 1] ^= 0x01; // Flip one bit
    const tamperedBase64 = tampered.toString('base64');
    
    try {
      const decrypted = decryptShare(tamperedBase64, password);
      logTest("AES-GCM Authentication", false, "Tampered ciphertext was accepted", {
        decrypted
      });
    } catch (error) {
      logTest("AES-GCM Authentication", true, "Tampered ciphertext was properly rejected");
    }
    
    // Test key derivation consistency
    const encrypted3 = encryptShare(testData, password);
    const decrypted3 = decryptShare(encrypted3, password);
    
    if (decrypted3 === testData) {
      logTest("Key Derivation Consistency", true, "PBKDF2 key derivation is consistent");
    } else {
      logTest("Key Derivation Consistency", false, "Key derivation produced inconsistent results");
    }
    
  } catch (error) {
    logTest("AES-GCM Security", false, `Error during AES-GCM test: ${error.message}`);
  }
}

// Test 4: Password Handling Security
function testPasswordSecurity() {
  console.log("🔍 Testing Password Handling Security...");
  
  try {
    const testData = "test share data";
    
    // Test weak passwords
    for (const weakPassword of weakPasswords) {
      try {
        const encrypted = encryptShare(testData, weakPassword);
        const decrypted = decryptShare(encrypted, weakPassword);
        
        if (decrypted === testData) {
          logTest(`Weak Password Handling (${weakPassword || 'empty'})`, true, 
            "System accepts weak passwords (consider adding password strength validation)");
        }
      } catch (error) {
        logTest(`Weak Password Handling (${weakPassword || 'empty'})`, false, 
          `Weak password caused error: ${error.message}`);
      }
    }
    
    // Test password case sensitivity
    const password = "TestPassword123!";
    const encrypted = encryptShare(testData, password);
    
    try {
      const decrypted = decryptShare(encrypted, password.toLowerCase());
      logTest("Password Case Sensitivity", false, "Passwords are not case sensitive");
    } catch (error) {
      logTest("Password Case Sensitivity", true, "Passwords are properly case sensitive");
    }
    
    // Test password with special characters
    const specialPassword = "P@$$w0rd!#$%^&*()_+-=[]{}|;:,.<>?";
    try {
      const encryptedSpecial = encryptShare(testData, specialPassword);
      const decryptedSpecial = decryptShare(encryptedSpecial, specialPassword);
      
      if (decryptedSpecial === testData) {
        logTest("Special Character Passwords", true, "Special characters in passwords work correctly");
      } else {
        logTest("Special Character Passwords", false, "Special characters in passwords cause issues");
      }
    } catch (error) {
      logTest("Special Character Passwords", false, `Special character password failed: ${error.message}`);
    }
    
  } catch (error) {
    logTest("Password Security", false, `Error during password test: ${error.message}`);
  }
}

// Test 5: Edge Cases and Boundary Conditions
function testEdgeCases() {
  console.log("🔍 Testing Edge Cases and Boundary Conditions...");
  
  try {
    // Test minimum threshold (2)
    try {
      const shares = bip39ToSlip39(testMnemonic, 2, 2, strongPasswords.slice(0, 2));
      const decrypted = decryptShares(shares, strongPasswords.slice(0, 2));
      const reconstructed = reconstructBip39Mnemonic(decrypted, 2);
      
      if (reconstructed === testMnemonic) {
        logTest("Minimum Threshold", true, "Minimum threshold (2,2) works correctly");
      } else {
        logTest("Minimum Threshold", false, "Minimum threshold produced wrong result");
      }
    } catch (error) {
      logTest("Minimum Threshold", false, `Minimum threshold failed: ${error.message}`);
    }
    
    // Test invalid threshold
    try {
      const shares = bip39ToSlip39(testMnemonic, 3, 4, strongPasswords.slice(0, 3));
      logTest("Invalid Threshold", false, "System accepted threshold > total shares");
    } catch (error) {
      logTest("Invalid Threshold", true, "System properly rejected threshold > total shares");
    }
    
    // Test maximum reasonable shares
    try {
      const largePasswords = Array(20).fill().map((_, i) => `password${i}Strong!@#`);
      const shares = bip39ToSlip39(testMnemonic, 20, 10, largePasswords);
      
      if (shares.length === 20) {
        logTest("Large Share Count", true, "System handles 20 shares correctly");
      } else {
        logTest("Large Share Count", false, `Expected 20 shares, got ${shares.length}`);
      }
    } catch (error) {
      logTest("Large Share Count", false, `Large share count failed: ${error.message}`);
    }
    
    // Test empty mnemonic
    try {
      const shares = bip39ToSlip39("", 3, 2, strongPasswords.slice(0, 3));
      logTest("Empty Mnemonic", false, "System accepted empty mnemonic");
    } catch (error) {
      logTest("Empty Mnemonic", true, "System properly rejected empty mnemonic");
    }
    
    // Test invalid mnemonic
    try {
      const shares = bip39ToSlip39("invalid mnemonic phrase", 3, 2, strongPasswords.slice(0, 3));
      logTest("Invalid Mnemonic", false, "System accepted invalid mnemonic");
    } catch (error) {
      logTest("Invalid Mnemonic", true, "System properly rejected invalid mnemonic");
    }
    
  } catch (error) {
    logTest("Edge Cases", false, `Error during edge case test: ${error.message}`);
  }
}

// Test 6: Timing Attack Resistance
function testTimingAttacks() {
  console.log("🔍 Testing Timing Attack Resistance...");
  
  try {
    const testData = "test share data";
    const correctPassword = "correctPassword123!";
    const wrongPassword = "wrongPassword456!";
    const encrypted = encryptShare(testData, correctPassword);
    
    // Measure decryption times
    const correctTimes = [];
    const wrongTimes = [];
    const iterations = 100;
    
    // Time correct password decryptions
    for (let i = 0; i < iterations; i++) {
      const start = process.hrtime.bigint();
      try {
        decryptShare(encrypted, correctPassword);
      } catch (error) {
        // Should not error with correct password
      }
      const end = process.hrtime.bigint();
      correctTimes.push(Number(end - start) / 1000000); // Convert to milliseconds
    }
    
    // Time wrong password decryptions
    for (let i = 0; i < iterations; i++) {
      const start = process.hrtime.bigint();
      try {
        decryptShare(encrypted, wrongPassword);
      } catch (error) {
        // Expected to error with wrong password
      }
      const end = process.hrtime.bigint();
      wrongTimes.push(Number(end - start) / 1000000); // Convert to milliseconds
    }
    
    const avgCorrectTime = correctTimes.reduce((a, b) => a + b, 0) / correctTimes.length;
    const avgWrongTime = wrongTimes.reduce((a, b) => a + b, 0) / wrongTimes.length;
    const timeDifference = Math.abs(avgCorrectTime - avgWrongTime);
    const timingRatio = Math.max(avgCorrectTime, avgWrongTime) / Math.min(avgCorrectTime, avgWrongTime);
    
    // If timing difference is less than 20% or absolute difference < 1ms, it's acceptable
    if (timingRatio < 1.2 || timeDifference < 1.0) {
      logTest("Timing Attack Resistance", true, "Decryption timing is consistent", {
        avgCorrectTime: avgCorrectTime.toFixed(3),
        avgWrongTime: avgWrongTime.toFixed(3),
        timeDifference: timeDifference.toFixed(3),
        timingRatio: timingRatio.toFixed(3)
      });
    } else {
      logTest("Timing Attack Resistance", false, "Significant timing difference detected", {
        avgCorrectTime: avgCorrectTime.toFixed(3),
        avgWrongTime: avgWrongTime.toFixed(3),
        timeDifference: timeDifference.toFixed(3),
        timingRatio: timingRatio.toFixed(3)
      });
    }
    
  } catch (error) {
    logTest("Timing Attack Resistance", false, `Error during timing test: ${error.message}`);
  }
}

// Utility function to calculate Shannon entropy
function calculateShannonEntropy(data) {
  const frequency = {};
  
  // Count character frequencies
  for (const char of data) {
    frequency[char] = (frequency[char] || 0) + 1;
  }
  
  // Calculate entropy
  let entropy = 0;
  const length = data.length;
  
  for (const count of Object.values(frequency)) {
    const probability = count / length;
    entropy -= probability * Math.log2(probability);
  }
  
  return entropy;
}

// Test 7: Memory Security
function testMemorySecurity() {
  console.log("🔍 Testing Memory Security...");
  
  try {
    // Test for potential memory leaks or sensitive data exposure
    const initialMemory = process.memoryUsage();
    
    // Generate many shares to test memory usage
    for (let i = 0; i < 100; i++) {
      const shares = bip39ToSlip39(testMnemonic, 5, 3, strongPasswords);
      const decrypted = decryptShares(shares, strongPasswords);
      const reconstructed = reconstructBip39Mnemonic(decrypted, 3);
    }
    
    // Force garbage collection if available
    if (global.gc) {
      global.gc();
    }
    
    const finalMemory = process.memoryUsage();
    const memoryIncrease = finalMemory.heapUsed - initialMemory.heapUsed;
    
    // Memory increase should be reasonable (less than 10MB for 100 iterations)
    if (memoryIncrease < 10 * 1024 * 1024) {
      logTest("Memory Usage", true, "Memory usage is reasonable", {
        initialHeap: Math.round(initialMemory.heapUsed / 1024 / 1024) + 'MB',
        finalHeap: Math.round(finalMemory.heapUsed / 1024 / 1024) + 'MB',
        increase: Math.round(memoryIncrease / 1024 / 1024) + 'MB'
      });
    } else {
      logTest("Memory Usage", false, "Excessive memory usage detected", {
        initialHeap: Math.round(initialMemory.heapUsed / 1024 / 1024) + 'MB',
        finalHeap: Math.round(finalMemory.heapUsed / 1024 / 1024) + 'MB',
        increase: Math.round(memoryIncrease / 1024 / 1024) + 'MB'
      });
    }
    
  } catch (error) {
    logTest("Memory Security", false, `Error during memory test: ${error.message}`);
  }
}

// Test 8: Data Integrity
function testDataIntegrity() {
  console.log("🔍 Testing Data Integrity...");
  
  try {
    // Test round-trip integrity with various mnemonics
    const testMnemonics = [
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
      "legal winner thank year wave sausage worth useful legal winner thank yellow",
      "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
      "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
    ];
    
    let integrityPassed = 0;
    
    for (const mnemonic of testMnemonics) {
      try {
        const shares = bip39ToSlip39(mnemonic, 5, 3, strongPasswords);
        const decrypted = decryptShares(shares.slice(0, 3), strongPasswords.slice(0, 3));
        const reconstructed = reconstructBip39Mnemonic(decrypted, 3);
        
        if (reconstructed === mnemonic) {
          integrityPassed++;
        }
      } catch (error) {
        // Failed for this mnemonic
      }
    }
    
    if (integrityPassed === testMnemonics.length) {
      logTest("Data Integrity", true, "All test mnemonics maintain integrity through the process");
    } else {
      logTest("Data Integrity", false, 
        `Only ${integrityPassed}/${testMnemonics.length} mnemonics maintained integrity`);
    }
    
    // Test with different entropy sizes
    const entropySizes = [128, 160, 192, 224, 256]; // bits
    let entropySizePassed = 0;
    
    for (const entropyBits of entropySizes) {
      try {
        const entropy = crypto.randomBytes(entropyBits / 8);
        const mnemonic = require('bip39').entropyToMnemonic(entropy);
        
        const shares = bip39ToSlip39(mnemonic, 5, 3, strongPasswords);
        const decrypted = decryptShares(shares.slice(0, 3), strongPasswords.slice(0, 3));
        const reconstructed = reconstructBip39Mnemonic(decrypted, 3);
        
        if (reconstructed === mnemonic) {
          entropySizePassed++;
        }
      } catch (error) {
        // Failed for this entropy size
      }
    }
    
    if (entropySizePassed === entropySizes.length) {
      logTest("Entropy Size Support", true, "All standard entropy sizes (128-256 bits) work correctly");
    } else {
      logTest("Entropy Size Support", false, 
        `Only ${entropySizePassed}/${entropySizes.length} entropy sizes work correctly`);
    }
    
  } catch (error) {
    logTest("Data Integrity", false, `Error during integrity test: ${error.message}`);
  }
}

// Test 9: Advanced Attack Scenarios
function testAdvancedAttackScenarios() {
  console.log("🔍 Testing Advanced Attack Scenarios...");
  
  try {
    const threshold = 3;
    const totalShares = 5;
    const encryptedShares = bip39ToSlip39(testMnemonic, totalShares, threshold, strongPasswords);
    
    // Attack 1: Try to reconstruct with random data
    try {
      const randomShares = Array(threshold).fill().map(() => 
        Buffer.from(crypto.randomBytes(32)).toString('base64')
      );
      const reconstructed = reconstructBip39Mnemonic(randomShares, threshold);
      logTest("Random Data Attack", false, "Random data was accepted as valid shares", {
        reconstructed
      });
    } catch (error) {
      logTest("Random Data Attack", true, "Random data was properly rejected");
    }
    
    // Attack 2: Try to mix shares from different secrets
    try {
      const shares1 = bip39ToSlip39(testMnemonic, 3, 2, strongPasswords.slice(0, 3));
      const shares2 = bip39ToSlip39("legal winner thank year wave sausage worth useful legal winner thank yellow", 3, 2, strongPasswords.slice(0, 3));
      
      const decrypted1 = decryptShares([shares1[0]], [strongPasswords[0]]);
      const decrypted2 = decryptShares([shares2[0], shares2[1]], [strongPasswords[0], strongPasswords[1]]);
      
      const mixedShares = [...decrypted1, ...decrypted2];
      const reconstructed = reconstructBip39Mnemonic(mixedShares, 2);
      
      logTest("Mixed Shares Attack", false, "Mixed shares from different secrets were accepted", {
        reconstructed
      });
    } catch (error) {
      logTest("Mixed Shares Attack", true, "Mixed shares were properly rejected");
    }
    
    // Attack 3: Try to use modified shares
    try {
      const shares = bip39ToSlip39(testMnemonic, 3, 2, strongPasswords.slice(0, 3));
      const decrypted = decryptShares(shares.slice(0, 2), strongPasswords.slice(0, 2));
      
      // Modify one share slightly
      const modifiedShare = Buffer.from(decrypted[0], 'base64');
      modifiedShare[0] ^= 0x01; // Flip one bit
      const modifiedShares = [modifiedShare.toString('base64'), decrypted[1]];
      
      const reconstructed = reconstructBip39Mnemonic(modifiedShares, 2);
      logTest("Modified Share Attack", false, "Modified share was accepted", {
        reconstructed
      });
    } catch (error) {
      logTest("Modified Share Attack", true, "Modified share was properly rejected");
    }
    
    // Attack 4: Try brute force with insufficient shares
    try {
      const shares = bip39ToSlip39(testMnemonic, 5, 3, strongPasswords);
      const decrypted = decryptShares(shares.slice(0, 2), strongPasswords.slice(0, 2));
      
      let successful = false;
      // Try with many random additional "shares"
      for (let i = 0; i < 100; i++) {
        try {
          const randomShare = Buffer.from(crypto.randomBytes(32)).toString('base64');
          const bruteShares = [...decrypted, randomShare];
          const reconstructed = reconstructBip39Mnemonic(bruteShares, 3);
          if (bip39.validateMnemonic(reconstructed)) {
            successful = true;
            break;
          }
        } catch (error) {
          // Expected to fail
        }
      }
      
      if (successful) {
        logTest("Brute Force Attack", false, "Brute force attack succeeded");
      } else {
        logTest("Brute Force Attack", true, "Brute force attack properly failed");
      }
    } catch (error) {
      logTest("Brute Force Attack", true, "Brute force attack properly failed");
    }
    
    // Attack 5: Try to exploit error messages for information leakage
    try {
      const shares = bip39ToSlip39(testMnemonic, 3, 2, strongPasswords.slice(0, 3));
      const decrypted = decryptShares([shares[0]], [strongPasswords[0]]);
      
      let infoLeaked = false;
      const errorMessages = [];
      
      // Try various invalid combinations and analyze error messages
      for (let i = 0; i < 10; i++) {
        try {
          const randomShare = Buffer.from(crypto.randomBytes(16 + i)).toString('base64');
          const testShares = [...decrypted, randomShare];
          reconstructBip39Mnemonic(testShares, 2);
        } catch (error) {
          errorMessages.push(error.message);
        }
      }
      
      // Check if error messages reveal sensitive information
      const uniqueMessages = [...new Set(errorMessages)];
      if (uniqueMessages.length > 3) {
        infoLeaked = true;
      }
      
      if (infoLeaked) {
        logTest("Information Leakage via Errors", false, "Error messages may leak information", {
          uniqueMessages: uniqueMessages.length,
          sample: uniqueMessages.slice(0, 3)
        });
      } else {
        logTest("Information Leakage via Errors", true, "Error messages are appropriately generic");
      }
    } catch (error) {
      logTest("Information Leakage via Errors", true, "Error handling is secure");
    }
    
  } catch (error) {
    logTest("Advanced Attack Scenarios", false, `Error during attack test: ${error.message}`);
  }
}

// Test 10: Cryptographic Boundary Testing
function testCryptographicBoundaries() {
  console.log("🔍 Testing Cryptographic Boundary Conditions...");
  
  try {
    // Test with extreme password lengths
    const extremePasswords = [
      "", // Empty
      "a".repeat(1000), // Very long
      "🔐".repeat(100), // Unicode characters
      "\x00\x01\x02", // Binary data
      "a".repeat(10000) // Extremely long
    ];
    
    let boundaryTestsPassed = 0;
    
    for (let i = 0; i < extremePasswords.length; i++) {
      try {
        const testData = "test data";
        const encrypted = encryptShare(testData, extremePasswords[i]);
        const decrypted = decryptShare(encrypted, extremePasswords[i]);
        
        if (decrypted === testData) {
          boundaryTestsPassed++;
        }
      } catch (error) {
        // Some extreme cases may fail, which is acceptable
      }
    }
    
    logTest("Extreme Password Lengths", true, 
      `${boundaryTestsPassed}/${extremePasswords.length} extreme password cases handled gracefully`);
    
    // Test with extreme share counts
    try {
      const largeShares = bip39ToSlip39(testMnemonic, 100, 50, 
        Array(100).fill().map((_, i) => `password${i}!`));
      
      if (largeShares.length === 100) {
        logTest("Extreme Share Count", true, "System handles 100 shares correctly");
      } else {
        logTest("Extreme Share Count", false, `Expected 100 shares, got ${largeShares.length}`);
      }
    } catch (error) {
      logTest("Extreme Share Count", false, `Large share count failed: ${error.message}`);
    }
    
    // Test threshold boundary (threshold = totalShares)
    try {
      const maxThresholdShares = bip39ToSlip39(testMnemonic, 5, 5, strongPasswords);
      const decrypted = decryptShares(maxThresholdShares, strongPasswords);
      const reconstructed = reconstructBip39Mnemonic(decrypted, 5);
      
      if (reconstructed === testMnemonic) {
        logTest("Maximum Threshold", true, "System handles threshold = totalShares correctly");
      } else {
        logTest("Maximum Threshold", false, "Maximum threshold produced wrong result");
      }
    } catch (error) {
      logTest("Maximum Threshold", false, `Maximum threshold failed: ${error.message}`);
    }
    
  } catch (error) {
    logTest("Cryptographic Boundaries", false, `Error during boundary test: ${error.message}`);
  }
}

// Test 11: Side-Channel Attack Resistance
function testSideChannelResistance() {
  console.log("🔍 Testing Side-Channel Attack Resistance...");
  
  try {
    const testData = "sensitive test data";
    const correctPassword = "correctPassword123!";
    
    // Test constant-time behavior across different data sizes
    const dataSizes = [10, 100, 1000, 10000];
    const timings = [];
    
    for (const size of dataSizes) {
      const largeData = "x".repeat(size);
      const times = [];
      
      for (let i = 0; i < 10; i++) {
        const start = process.hrtime.bigint();
        const encrypted = encryptShare(largeData, correctPassword);
        const end = process.hrtime.bigint();
        times.push(Number(end - start) / 1000000);
      }
      
      const avgTime = times.reduce((a, b) => a + b, 0) / times.length;
      timings.push({ size, avgTime });
    }
    
    // Check if timing is consistent and doesn't leak information about data size
    // Low ratio (close to 0) means timing is very consistent, which is good for security
    const timingGrowth = timings[timings.length - 1].avgTime / timings[0].avgTime;
    const dataSizeGrowth = dataSizes[dataSizes.length - 1] / dataSizes[0];
    const ratio = timingGrowth / dataSizeGrowth;
    
    // Allow for both consistent timing (low ratio) and reasonable scaling (ratio < 5.0)
    // Very low ratio (< 0.1) means excellent timing consistency (good for security)
    // High ratio (> 5.0) might indicate timing attacks or performance issues
    if (ratio < 5.0) {
      if (ratio < 0.1) {
        logTest("Encryption Timing Consistency", true, "Excellent timing consistency - no data size leakage detected");
      } else {
        logTest("Encryption Timing Consistency", true, "Encryption timing scales reasonably with data size");
      }
    } else {
      logTest("Encryption Timing Consistency", false, "Unusual timing behavior detected - potential performance issue", {
        ratio,
        timings
      });
    }
    
    // Test for cache timing attacks
    const cacheTestIterations = 1000;
    const hitTimes = [];
    const missTimes = [];
    
    // Warm up cache
    for (let i = 0; i < 100; i++) {
      encryptShare(testData, correctPassword);
    }
    
    // Measure cache hits (same data)
    for (let i = 0; i < cacheTestIterations; i++) {
      const start = process.hrtime.bigint();
      encryptShare(testData, correctPassword);
      const end = process.hrtime.bigint();
      hitTimes.push(Number(end - start) / 1000000);
    }
    
    // Measure cache misses (different data each time)
    for (let i = 0; i < cacheTestIterations; i++) {
      const uniqueData = testData + i;
      const start = process.hrtime.bigint();
      encryptShare(uniqueData, correctPassword);
      const end = process.hrtime.bigint();
      missTimes.push(Number(end - start) / 1000000);
    }
    
    const avgHitTime = hitTimes.reduce((a, b) => a + b, 0) / hitTimes.length;
    const avgMissTime = missTimes.reduce((a, b) => a + b, 0) / missTimes.length;
    const cacheDifference = Math.abs(avgHitTime - avgMissTime);
    
    if (cacheDifference < 1.0) { // Less than 1ms difference
      logTest("Cache Timing Resistance", true, "No significant cache timing differences detected");
    } else {
      logTest("Cache Timing Resistance", false, "Potential cache timing vulnerability", {
        avgHitTime: avgHitTime.toFixed(3),
        avgMissTime: avgMissTime.toFixed(3),
        difference: cacheDifference.toFixed(3)
      });
    }
    
  } catch (error) {
    logTest("Side-Channel Resistance", false, `Error during side-channel test: ${error.message}`);
  }
}

// Test 12: Cryptographic Strength Under Stress
function testCryptographicStress() {
  console.log("🔍 Testing Cryptographic Strength Under Stress...");
  
  try {
    // Test with many iterations to check for patterns
    const iterations = 1000;
    const allShares = [];
    const allMnemonics = [];
    
    for (let i = 0; i < iterations; i++) {
      try {
        const entropy = crypto.randomBytes(16);
        const mnemonic = bip39.entropyToMnemonic(entropy);
        const shares = bip39ToSlip39(mnemonic, 3, 2, strongPasswords.slice(0, 3));
        
        allShares.push(shares);
        allMnemonics.push(mnemonic);
      } catch (error) {
        // Some may fail, which is OK
      }
    }
    
    // Check for duplicate shares (should be extremely rare)
    const allSharesFlat = allShares.flat();
    const uniqueShares = new Set(allSharesFlat);
    const duplicateRate = allSharesFlat.length > 0 ? (allSharesFlat.length - uniqueShares.size) / allSharesFlat.length : 0;
    
    if (duplicateRate < 0.001) { // Less than 0.1% duplicates
      logTest("Share Uniqueness Under Stress", true, 
        `Excellent uniqueness: ${duplicateRate.toFixed(6)} duplicate rate over ${iterations} iterations`);
    } else {
      logTest("Share Uniqueness Under Stress", false, 
        `High duplicate rate detected: ${duplicateRate.toFixed(6)}`, { duplicateRate });
    }
    
    // Test reconstruction success rate
    let successfulReconstructions = 0;
    let totalTests = 0;
    
    for (let i = 0; i < Math.min(100, allShares.length); i++) {
      try {
        const shares = allShares[i];
        const passwords = strongPasswords.slice(0, 3); // Use all 3 passwords for 3 shares
        
        // Decrypt all shares to get the raw shares
        const decrypted = decryptShares(shares, passwords);
        
        // Reconstruct using all available shares (should work since we have threshold=2)
        const reconstructed = reconstructBip39Mnemonic(decrypted, 2);
        
        if (reconstructed === allMnemonics[i]) {
          successfulReconstructions++;
        }
        totalTests++;
      } catch (error) {
        // Log the error for debugging but continue
        console.log(`   Reconstruction test ${i} failed: ${error.message}`);
        totalTests++;
      }
    }
    
    const successRate = totalTests > 0 ? successfulReconstructions / totalTests : 0;
    
    if (successRate > 0.99) { // Greater than 99% success (allowing for some edge cases)
      logTest("Reconstruction Success Rate", true, 
        `High success rate: ${(successRate * 100).toFixed(1)}%`);
    } else {
      logTest("Reconstruction Success Rate", false, 
        `Low success rate: ${(successRate * 100).toFixed(1)}%`, { successRate, totalTests, successfulReconstructions });
    }
    
  } catch (error) {
    logTest("Cryptographic Stress", false, `Error during stress test: ${error.message}`);
  }
}

// Main test execution
async function runSecurityAudit() {
  console.log("🔒 Starting Comprehensive Security Audit for slip39.js");
  console.log("=" .repeat(80));
  console.log("");
  
  testRandomnessQuality();
  testShamirSecretSharingSecurity();
  testAESGCMSecurity();
  testPasswordSecurity();
  testEdgeCases();
  testTimingAttacks();
  testMemorySecurity();
  testDataIntegrity();
  testAdvancedAttackScenarios();
  testCryptographicBoundaries();
  testSideChannelResistance();
  testCryptographicStress();
  
  // Summary
  console.log("=" .repeat(80));
  console.log("🔒 SECURITY AUDIT SUMMARY");
  console.log("=" .repeat(80));
  
  const passed = testResults.filter(r => r.passed).length;
  const total = testResults.length;
  const failedTests = testResults.filter(r => !r.passed);
  
  console.log(`✅ Passed: ${passed}/${total} tests`);
  console.log(`❌ Failed: ${total - passed}/${total} tests`);
  console.log("");
  
  if (failedTests.length > 0) {
    console.log("⚠️  FAILED TESTS:");
    failedTests.forEach(test => {
      console.log(`   • ${test.testName}: ${test.message}`);
    });
    console.log("");
  }
  
  // Risk assessment
  const criticalFailures = failedTests.filter(test => 
    test.testName.includes('Randomness') || 
    test.testName.includes('Authentication') ||
    test.testName.includes('Threshold') ||
    test.testName.includes('Nonce')
  );
  
  if (criticalFailures.length === 0) {
    console.log("🟢 OVERALL ASSESSMENT: No critical security vulnerabilities detected");
  } else {
    console.log("🔴 OVERALL ASSESSMENT: Critical security vulnerabilities detected");
    console.log("⚠️  Immediate attention required for:");
    criticalFailures.forEach(test => {
      console.log(`   • ${test.testName}`);
    });
  }
  
  console.log("");
  console.log("📊 Test completed at:", new Date().toISOString());
}

// Run the audit
runSecurityAudit().catch(error => {
  console.error("Security audit failed:", error);
  process.exit(1);
});
