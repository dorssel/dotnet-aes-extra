// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Diagnostics;
using System.IO.Pipelines;

namespace UnitTests;

[TestClass]
sealed class AesSiv_Tests
{
    static readonly byte[] TestKey = new byte[32];
    static readonly byte[] TestPlaintext = new byte[23];
    static readonly byte[] TestCiphertext = new byte[16 + TestPlaintext.Length];

    [TestMethod]
    [DataRow(256)]
    [DataRow(384)]
    [DataRow(512)]
    public void Constructor_WithKey(int keySize)
    {
        using var aesSiv = new AesSiv(new byte[keySize / 8]);
    }

    [TestMethod]
    public void Constructor_WithInvalidKeySize()
    {
        Assert.ThrowsException<CryptographicException>(() =>
        {
            using var aesSiv = new AesSiv(new byte[42]);
        });
    }

    [TestMethod]
    public void Constructor_WithNullKey()
    {
        Assert.ThrowsException<ArgumentNullException>(() =>
        {
            using var aesSiv = new AesSiv(null!);
        });
    }

    [TestMethod]
    public void Dispose()
    {
        var aesSiv = new AesSiv(TestKey);
        aesSiv.Dispose();
    }

    [TestMethod]
    public void Dispose_Double()
    {
        var aesSiv = new AesSiv(TestKey);
        aesSiv.Dispose();
        aesSiv.Dispose();
    }

    [TestMethod]
    public void LegalKeySizes_Get()
    {
        var legalKeySizes = new SortedSet<int>();
        foreach (var legalKeySize in AesSiv.LegalKeySizes)
        {
            for (var keySize = legalKeySize.MinSize; keySize <= legalKeySize.MaxSize; keySize += Math.Max(legalKeySize.SkipSize, 1))
            {
                Assert.IsFalse(legalKeySizes.Contains(keySize));
                legalKeySizes.Add(keySize);
            }
        }
        Assert.IsTrue(Enumerable.SequenceEqual(new SortedSet<int>() { 256, 384, 512 }, legalKeySizes));
    }

    [TestMethod]
    [DataRow(256)]
    [DataRow(384)]
    [DataRow(512)]
    public void ValidKeySize_WithValidSize(int keySize)
    {
        Assert.IsTrue(AesSiv.ValidKeySize(keySize));
    }

    [TestMethod]
    [DataRow(0)]
    [DataRow(1)]
    [DataRow(128 / 8)]
    [DataRow(192 / 8)]
    [DataRow(256 / 8)]
    [DataRow(384 / 8)]
    [DataRow(512 / 8)]
    public void ValidKeySize_WithInvalidSize(int keySize)
    {
        Assert.IsFalse(AesSiv.ValidKeySize(keySize));
    }

    [TestMethod]
    public void Encrypt_NullPlaintextThrows()
    {
        using var aesSiv = new AesSiv(TestKey);
        Assert.ThrowsException<ArgumentNullException>(() =>
        {
            aesSiv.Encrypt(null!, TestCiphertext);
        });
    }

    [TestMethod]
    public void Encrypt_NullCiphertextThrows()
    {
        using var aesSiv = new AesSiv(TestKey);
        Assert.ThrowsException<ArgumentNullException>(() =>
        {
            aesSiv.Encrypt(TestPlaintext, null!);
        });
    }

    [TestMethod]
    public void Encrypt_NullAssociatedDataThrows()
    {
        using var aesSiv = new AesSiv(TestKey);
        Assert.ThrowsException<ArgumentNullException>(() =>
        {
            aesSiv.Encrypt(TestPlaintext, TestCiphertext, null!);
        });
    }

    [TestMethod]
    public void Encrypt_NullAssociatedDataItemThrows()
    {
        using var aesSiv = new AesSiv(TestKey);
        Assert.ThrowsException<ArgumentException>(() =>
        {
            aesSiv.Encrypt(TestPlaintext, TestCiphertext, new byte[][]
            {
                null!,
            });
        });
    }

    [TestMethod]
    public void Encrypt_InvalidCiphertextLengthThrows()
    {
        using var aesSiv = new AesSiv(TestKey);
        Assert.ThrowsException<ArgumentException>(() =>
        {
            aesSiv.Encrypt(TestPlaintext, new byte[TestCiphertext.Length + 1]);
        });
    }

    [TestMethod]
    public void Decrypt_NullCiphertextThrows()
    {
        using var aesSiv = new AesSiv(TestKey);
        Assert.ThrowsException<ArgumentNullException>(() =>
        {
            aesSiv.Decrypt(null!, TestPlaintext);
        });
    }

    [TestMethod]
    public void Decrypt_NullPlaintextThrows()
    {
        using var aesSiv = new AesSiv(TestKey);
        Assert.ThrowsException<ArgumentNullException>(() =>
        {
            aesSiv.Decrypt(TestCiphertext, null!);
        });
    }

    [TestMethod]
    public void Decrypt_NullAssociatedDataThrows()
    {
        using var aesSiv = new AesSiv(TestKey);
        Assert.ThrowsException<ArgumentNullException>(() =>
        {
            aesSiv.Decrypt(TestCiphertext, TestPlaintext, null!);
        });
    }

    [TestMethod]
    public void Decrypt_NullAssociatedDataItemThrows()
    {
        using var aesSiv = new AesSiv(TestKey);
        Assert.ThrowsException<ArgumentException>(() =>
        {
            aesSiv.Decrypt(TestCiphertext, TestPlaintext, new byte[][]
            {
                null!,
            });
        });
    }

    [TestMethod]
    public void Decrypt_InvalidCiphertextLengthThrows()
    {
        using var aesSiv = new AesSiv(TestKey);
        Assert.ThrowsException<ArgumentException>(() =>
        {
            aesSiv.Decrypt(new byte[15], TestPlaintext);
        });
    }

    [TestMethod]
    public void Decrypt_InvalidPlaintextLengthThrows()
    {
        using var aesSiv = new AesSiv(TestKey);
        Assert.ThrowsException<ArgumentException>(() =>
        {
            aesSiv.Decrypt(TestCiphertext, new byte[TestPlaintext.Length + 1]);
        });
    }

    [TestMethod]
    public void Decrypt_InvalidAuthenticationThrows()
    {
        using var aesSiv = new AesSiv(TestKey);
        aesSiv.Encrypt(TestPlaintext, TestCiphertext, new byte[] { 1 });
        Assert.ThrowsException<CryptographicException>(() =>
        {
            aesSiv.Decrypt(TestCiphertext, TestPlaintext, new byte[] { 2 });
        });
    }

    [TestMethod]
    public void EmptyPlaintext()
    {
        var cipherText = new byte[16];
        {
            using var aesSiv = new AesSiv(TestKey);
            aesSiv.Encrypt(Array.Empty<byte>(), cipherText);
            Assert.IsFalse(Enumerable.SequenceEqual(new byte[16], cipherText));
        }
        {
            using var aesSiv = new AesSiv(TestKey);
            aesSiv.Decrypt(cipherText, Array.Empty<byte>());
        }
        Assert.ThrowsException<CryptographicException>(() =>
        {
            using var aesSiv = new AesSiv(TestKey);
            aesSiv.Decrypt(cipherText, Array.Empty<byte>(), new byte[] { 2 });
        });
    }

    [TestMethod]
    public void EncryptDecrypt_Reuse()
    {
        // one key
        var key = Enumerable.Range(3, 32).Select(i => (byte)i).ToArray();

        // two totally different messages
        var associatedData_1 = new byte[][]
        {
            Enumerable.Range(1001, 99).Select(i => (byte)i).ToArray(),
            Enumerable.Range(2001, 1).Select(i => (byte)i).ToArray(),
            Enumerable.Range(3001, 16).Select(i => (byte)i).ToArray(),
        };
        var plaintext_1 = Enumerable.Range(1, 207).Select(i => (byte)i).ToArray();
        var ciphertext_1 = new byte[16 + plaintext_1.Length];
        {
            using var aesSiv = new AesSiv(key);
            aesSiv.Encrypt(plaintext_1, ciphertext_1, associatedData_1);
        }

        var associatedData_2 = new byte[][]
        {
            Enumerable.Range(4001, 4).Select(i => (byte)i).ToArray(),
        };
        var plaintext_2 = Enumerable.Range(9, 5).Select(i => (byte)i).ToArray();
        var ciphertext_2 = new byte[16 + plaintext_2.Length];
        {
            using var aesSiv = new AesSiv(key);
            aesSiv.Encrypt(plaintext_2, ciphertext_2, associatedData_2);
        }

        // re-use the same instance (implies same key), mixing the messages
        {
            using var aesSiv = new AesSiv(key);

            // run everything a few times, mixing messages and Encrypt/Decrypt
            for (var i = 0; i < 2; ++i)
            {
                aesSiv.Encrypt(plaintext_1, new byte[ciphertext_1.Length], associatedData_1);
                aesSiv.Encrypt(plaintext_2, new byte[ciphertext_2.Length], associatedData_2);

                aesSiv.Decrypt(ciphertext_1, new byte[plaintext_1.Length], associatedData_1);
                aesSiv.Decrypt(ciphertext_2, new byte[plaintext_2.Length], associatedData_2);
            }

            // now the tests
            {
                var test = new byte[ciphertext_1.Length];
                aesSiv.Encrypt(plaintext_1, test, associatedData_1);
                Assert.IsTrue(Enumerable.SequenceEqual(ciphertext_1, test));
            }
            {
                var test = new byte[ciphertext_2.Length];
                aesSiv.Encrypt(plaintext_2, test, associatedData_2);
                Assert.IsTrue(Enumerable.SequenceEqual(ciphertext_2, test));
            }
            {
                var test = new byte[plaintext_1.Length];
                aesSiv.Decrypt(ciphertext_1, test, associatedData_1);
                Assert.IsTrue(Enumerable.SequenceEqual(plaintext_1, test));
            }
            {
                var test = new byte[plaintext_2.Length];
                aesSiv.Decrypt(ciphertext_2, test, associatedData_2);
                Assert.IsTrue(Enumerable.SequenceEqual(plaintext_2, test));
            }
        }
    }
}
