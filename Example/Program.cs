// SPDX-FileCopyrightText: 2025 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography;
using System.Security.Cryptography;

// example data
const int AesBlockSizeInBytes = 16;
var plaintext = new byte[] { 1, 2, 3 };
var key = RandomNumberGenerator.GetBytes(32);
var iv = RandomNumberGenerator.GetBytes(AesBlockSizeInBytes);
var salt = RandomNumberGenerator.GetBytes(8);
var associatedData = new byte[] { 4, 5 };

// AES-CTR (use like .NET's Aes)
using var aesCtr = new AesCtr(key);
var ciphertextCtr = aesCtr.TransformCtr(plaintext, iv);

// AES-CMAC (use like .NET's HMACSHA256)
using var aesCmac = new AesCmac(key);
var tagCmac = aesCmac.ComputeHash(plaintext);

// SIV-AES (use like .NET's AesGcm)
using var aesSiv = new AesSiv(key);
var ciphertextSiv = new byte[AesBlockSizeInBytes + plaintext.Length];
aesSiv.Encrypt(plaintext, ciphertextSiv, associatedData);

// AES-CMAC-PRF-128 (use like .NET's HKDF)
var derivedKey = AesCmacPrf128.DeriveKey(key, plaintext);

// PBKDF2-AES-CMAC-PRF-128 (use like .NET's Rfc2898DeriveBytes)
var passwordBasedDerivedKey = AesCmacPrf128.Pbkdf2("password", salt, 1000, 32);
