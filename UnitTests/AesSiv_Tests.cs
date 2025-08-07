// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

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
        Assert.ThrowsExactly<CryptographicException>(() =>
        {
            using var aesSiv = new AesSiv(new byte[42]);
        });
    }

    [TestMethod]
    public void Constructor_WithNullKey()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() =>
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
    public void Encrypt_Array_Array_Array_MaximumItems()
    {
        var associatedData = Enumerable.Range(1, 126).Select(i => Array.Empty<byte>()).ToArray();

        using var aesSiv = new AesSiv(TestKey);
        aesSiv.Encrypt(TestPlaintext, new byte[TestCiphertext.Length], associatedData);
    }

    [TestMethod]
    public void Encrypt_Array_Array_Array_PlaintextNull()
    {
        using var aesSiv = new AesSiv(TestKey);
        Assert.ThrowsExactly<ArgumentNullException>(() =>
        {
            aesSiv.Encrypt(null!, new byte[TestCiphertext.Length]);
        });
    }

    [TestMethod]
    public void Encrypt_Array_Array_Array_CiphertextNull()
    {
        using var aesSiv = new AesSiv(TestKey);
        Assert.ThrowsExactly<ArgumentNullException>(() =>
        {
            aesSiv.Encrypt(TestPlaintext, null!);
        });
    }

    [TestMethod]
    public void Encrypt_Array_Array_Array_CiphertextInvalidLength()
    {
        using var aesSiv = new AesSiv(TestKey);
        Assert.ThrowsExactly<ArgumentException>(() =>
        {
            aesSiv.Encrypt(TestPlaintext, new byte[TestCiphertext.Length + 1]);
        });
    }

    [TestMethod]
    public void Encrypt_Array_Array_Array_AssociatedDataNull()
    {
        using var aesSiv = new AesSiv(TestKey);
        Assert.ThrowsExactly<ArgumentNullException>(() =>
        {
            aesSiv.Encrypt(TestPlaintext, new byte[TestCiphertext.Length], null!);
        });
    }

    [TestMethod]
    public void Encrypt_Array_Array_Array_AssociatedDataItemNull()
    {
        using var aesSiv = new AesSiv(TestKey);
        Assert.ThrowsExactly<ArgumentException>(() =>
        {
            aesSiv.Encrypt(TestPlaintext, new byte[TestCiphertext.Length], [null!]);
        });
    }

    [TestMethod]
    public void Encrypt_Array_Array_Array_AssociatedDataTooManyItems()
    {
        var associatedData = Enumerable.Range(1, 127).Select(i => Array.Empty<byte>()).ToArray();

        using var aesSiv = new AesSiv(TestKey);
        Assert.ThrowsExactly<ArgumentException>(() =>
        {
            aesSiv.Encrypt(TestPlaintext, new byte[TestCiphertext.Length], associatedData);
        });
    }

    [TestMethod]
    public void Encrypt_Array_Array_Array_AfterDispose()
    {
        using var aesSiv = new AesSiv(TestKey);
        aesSiv.Dispose();
        Assert.ThrowsExactly<ObjectDisposedException>(() =>
        {
            aesSiv.Encrypt(TestPlaintext, new byte[TestCiphertext.Length]);
        });
    }

    [TestMethod]
    public void Encrypt_ReadOnlySpan_Span_ReadOnlySpan_CiphertextInvalidLength()
    {
        using var aesSiv = new AesSiv(TestKey);
        Assert.ThrowsExactly<ArgumentException>(() =>
        {
            aesSiv.Encrypt(TestPlaintext.AsSpan(), new byte[TestCiphertext.Length + 1].AsSpan(), new Span<byte>());
        });
    }

    [TestMethod]
    public void Encrypt_ReadOnlySpan_Span_ReadOnlySpan_AfterDispose()
    {
        using var aesSiv = new AesSiv(TestKey);
        aesSiv.Dispose();
        Assert.ThrowsExactly<ObjectDisposedException>(() =>
        {
            aesSiv.Encrypt(TestPlaintext.AsSpan(), new byte[TestCiphertext.Length].AsSpan(), new Span<byte>());
        });
    }

    [TestMethod]
    public void Encrypt_ReadOnlySpan_Span_ReadOnlyMemories_MaximumItems()
    {
        var associatedData = Enumerable.Range(1, 126).Select(i => new ReadOnlyMemory<byte>()).ToArray();

        using var aesSiv = new AesSiv(TestKey);
        aesSiv.Encrypt(TestPlaintext.AsSpan(), new byte[TestCiphertext.Length].AsSpan(), associatedData.AsSpan());
    }

    [TestMethod]
    public void Encrypt_ReadOnlySpan_Span_ReadOnlyMemories_CiphertextInvalidLength()
    {
        using var aesSiv = new AesSiv(TestKey);
        Assert.ThrowsExactly<ArgumentException>(() =>
        {
            aesSiv.Encrypt(TestPlaintext.AsSpan(), new byte[TestCiphertext.Length + 1].AsSpan());
        });
    }

    [TestMethod]
    public void Encrypt_ReadOnlySpan_Span_ReadOnlyMemories_AssociatedDataTooManyItems()
    {
        var associatedData = Enumerable.Range(1, 127).Select(i => new ReadOnlyMemory<byte>()).ToArray();

        using var aesSiv = new AesSiv(TestKey);
        Assert.ThrowsExactly<ArgumentException>(() =>
        {
            aesSiv.Encrypt(TestPlaintext.AsSpan(), new byte[TestCiphertext.Length].AsSpan(), associatedData.AsSpan());
        });
    }

    [TestMethod]
    public void Encrypt_ReadOnlySpan_Span_ReadOnlyMemories_AfterDispose()
    {
        using var aesSiv = new AesSiv(TestKey);
        aesSiv.Dispose();
        Assert.ThrowsExactly<ObjectDisposedException>(() =>
        {
            aesSiv.Encrypt(TestPlaintext.AsSpan(), new byte[TestCiphertext.Length].AsSpan());
        });
    }

    [TestMethod]
    public void Decrypt_Array_Array_Array_MaximumItems()
    {
        var associatedData = Enumerable.Range(1, 126).Select(i => Array.Empty<byte>()).ToArray();

        using var aesSiv = new AesSiv(TestKey);
        var cipherText = new byte[TestCiphertext.Length];
        aesSiv.Encrypt(TestPlaintext, cipherText, associatedData);
        aesSiv.Decrypt(cipherText, new byte[TestPlaintext.Length], associatedData);
    }

    [TestMethod]
    public void Decrypt_Array_Array_Array_CiphertextNull()
    {
        using var aesSiv = new AesSiv(TestKey);
        Assert.ThrowsExactly<ArgumentNullException>(() =>
        {
            aesSiv.Decrypt(null!, new byte[TestPlaintext.Length]);
        });
    }

    [TestMethod]
    public void Decrypt_Array_Array_Array_CiphertextInvalidLength()
    {
        using var aesSiv = new AesSiv(TestKey);
        Assert.ThrowsExactly<ArgumentException>(() =>
        {
            aesSiv.Decrypt(new byte[15], new byte[TestPlaintext.Length]);
        });
    }

    [TestMethod]
    public void Decrypt_Array_Array_Array_PlaintextNull()
    {
        using var aesSiv = new AesSiv(TestKey);
        Assert.ThrowsExactly<ArgumentNullException>(() =>
        {
            aesSiv.Decrypt(TestCiphertext, null!);
        });
    }

    [TestMethod]
    public void Decrypt_Array_Array_Array_PlaintextInvalidLength()
    {
        using var aesSiv = new AesSiv(TestKey);
        Assert.ThrowsExactly<ArgumentException>(() =>
        {
            aesSiv.Decrypt(TestCiphertext, new byte[TestPlaintext.Length + 1]);
        });
    }

    [TestMethod]
    public void Decrypt_Array_Array_Array_AssociatedDataNull()
    {
        using var aesSiv = new AesSiv(TestKey);
        Assert.ThrowsExactly<ArgumentNullException>(() =>
        {
            aesSiv.Decrypt(TestCiphertext, new byte[TestPlaintext.Length], null!);
        });
    }

    [TestMethod]
    public void Decrypt_Array_Array_Array_AssociatedDataItemNull()
    {
        using var aesSiv = new AesSiv(TestKey);
        Assert.ThrowsExactly<ArgumentException>(() =>
        {
            aesSiv.Decrypt(TestCiphertext, new byte[TestPlaintext.Length], [null!]);
        });
    }

    [TestMethod]
    public void Decrypt_Array_Array_Array_AssociatedDataTooManyItems()
    {
        var associatedData = Enumerable.Range(1, 127).Select(i => Array.Empty<byte>()).ToArray();

        using var aesSiv = new AesSiv(TestKey);
        Assert.ThrowsExactly<ArgumentException>(() =>
        {
            aesSiv.Decrypt(TestCiphertext, new byte[TestPlaintext.Length], associatedData);
        });
    }

    [TestMethod]
    public void Decrypt_Array_Array_Array_AuthenticationFailure()
    {
        using var aesSiv = new AesSiv(TestKey);
        aesSiv.Encrypt(TestPlaintext, TestCiphertext, new byte[] { 1 });
        Assert.ThrowsExactly<CryptographicException>(() =>
        {
            aesSiv.Decrypt(TestCiphertext, new byte[TestPlaintext.Length], new byte[] { 2 });
        });
    }

    [TestMethod]
    public void Decrypt_Array_Array_Array_AfterDispose()
    {
        using var aesSiv = new AesSiv(TestKey);
        aesSiv.Dispose();
        Assert.ThrowsExactly<ObjectDisposedException>(() =>
        {
            aesSiv.Decrypt(TestCiphertext, new byte[TestPlaintext.Length]);
        });
    }

    [TestMethod]
    public void Decrypt_ReadOnlySpan_Span_ReadOnlySpan_CiphertextInvalidLength()
    {
        using var aesSiv = new AesSiv(TestKey);
        Assert.ThrowsExactly<ArgumentException>(() =>
        {
            aesSiv.Decrypt(new byte[15].AsSpan(), new byte[TestPlaintext.Length].AsSpan(), new Span<byte>());
        });
    }

    [TestMethod]
    public void Decrypt_ReadOnlySpan_Span_ReadOnlySpan_PlaintextInvalidLength()
    {
        using var aesSiv = new AesSiv(TestKey);
        Assert.ThrowsExactly<ArgumentException>(() =>
        {
            aesSiv.Decrypt(TestCiphertext.AsSpan(), new byte[TestPlaintext.Length + 1].AsSpan(), new Span<byte>());
        });
    }

    [TestMethod]
    public void Decrypt_ReadOnlySpan_Span_ReadOnlySpan_AuthenticationFailure()
    {
        using var aesSiv = new AesSiv(TestKey);
        aesSiv.Encrypt(TestPlaintext, TestCiphertext, new byte[] { 1 });
        Assert.ThrowsExactly<CryptographicException>(() =>
        {
            aesSiv.Decrypt(TestCiphertext.AsSpan(), new byte[TestPlaintext.Length].AsSpan(), new Span<byte>());
        });
    }

    [TestMethod]
    public void Decrypt_ReadOnlySpan_Span_ReadOnlySpan_AfterDispose()
    {
        using var aesSiv = new AesSiv(TestKey);
        aesSiv.Dispose();
        Assert.ThrowsExactly<ObjectDisposedException>(() =>
        {
            aesSiv.Decrypt(TestCiphertext.AsSpan(), new byte[TestPlaintext.Length].AsSpan(), new Span<byte>());
        });
    }

    [TestMethod]
    public void Decrypt_ReadOnlySpan_Span_ReadOnlyMemories_MaximumItems()
    {
        var associatedData = Enumerable.Range(1, 126).Select(i => new ReadOnlyMemory<byte>()).ToArray();

        using var aesSiv = new AesSiv(TestKey);
        var cipherText = new byte[TestCiphertext.Length];
        aesSiv.Encrypt(TestPlaintext.AsSpan(), cipherText.AsSpan(), associatedData.AsSpan());
        aesSiv.Decrypt(cipherText.AsSpan(), new byte[TestPlaintext.Length].AsSpan(), associatedData.AsSpan());
    }

    [TestMethod]
    public void Decrypt_ReadOnlySpan_Span_ReadOnlyMemories_CiphertextInvalidLength()
    {
        using var aesSiv = new AesSiv(TestKey);
        Assert.ThrowsExactly<ArgumentException>(() =>
        {
            aesSiv.Decrypt(new byte[15].AsSpan(), new byte[TestPlaintext.Length].AsSpan());
        });
    }

    [TestMethod]
    public void Decrypt_ReadOnlySpan_Span_ReadOnlyMemories_PlaintextInvalidLength()
    {
        using var aesSiv = new AesSiv(TestKey);
        Assert.ThrowsExactly<ArgumentException>(() =>
        {
            aesSiv.Decrypt(TestCiphertext.AsSpan(), new byte[TestPlaintext.Length + 1].AsSpan());
        });
    }

    [TestMethod]
    public void Decrypt_ReadOnlySpan_Span_ReadOnlyMemories_AssociatedDataTooManyItems()
    {
        var associatedData = Enumerable.Range(1, 127).Select(i => new ReadOnlyMemory<byte>()).ToArray();

        using var aesSiv = new AesSiv(TestKey);
        Assert.ThrowsExactly<ArgumentException>(() =>
        {
            aesSiv.Decrypt(TestCiphertext.AsSpan(), new byte[TestPlaintext.Length].AsSpan(), associatedData.AsSpan());
        });
    }

    [TestMethod]
    public void Decrypt_ReadOnlySpan_Span_ReadOnlyMemories_AuthenticationFailure()
    {
        using var aesSiv = new AesSiv(TestKey);
        aesSiv.Encrypt(TestPlaintext, TestCiphertext, new byte[] { 1 });
        Assert.ThrowsExactly<CryptographicException>(() =>
        {
            aesSiv.Decrypt(TestCiphertext.AsSpan(), TestPlaintext.AsSpan());
        });
    }

    [TestMethod]
    public void Decrypt_ReadOnlySpan_Span_ReadOnlyMemories_AfterDispose()
    {
        using var aesSiv = new AesSiv(TestKey);
        aesSiv.Dispose();
        Assert.ThrowsExactly<ObjectDisposedException>(() =>
        {
            aesSiv.Decrypt(TestCiphertext.AsSpan(), new byte[TestPlaintext.Length].AsSpan());
        });
    }

    [TestMethod]
    public void EmptyPlaintext()
    {
        var cipherText = new byte[16];
        {
            using var aesSiv = new AesSiv(TestKey);
            aesSiv.Encrypt(Array.Empty<byte>(), cipherText);
            CollectionAssert.AreNotEqual(new byte[16], cipherText);
        }
        {
            using var aesSiv = new AesSiv(TestKey);
            aesSiv.Decrypt(cipherText, Array.Empty<byte>());
        }
        Assert.ThrowsExactly<CryptographicException>(() =>
        {
            using var aesSiv = new AesSiv(TestKey);
            aesSiv.Decrypt(cipherText, Array.Empty<byte>(), new byte[] { 2 });
        });
    }

    [TestMethod]
    public void EncryptDecrypt_Reuse()
    {
        // one key
        var key = Enumerable.Range(3, 32).ToUncheckedByteArray();

        // two totally different messages
        var associatedData_1 = new byte[][]
        {
            Enumerable.Range(1001, 99).ToUncheckedByteArray(),
            Enumerable.Range(2001, 1).ToUncheckedByteArray(),
            Enumerable.Range(3001, 16).ToUncheckedByteArray(),
        };
        var plaintext_1 = Enumerable.Range(1, 207).ToUncheckedByteArray();
        var ciphertext_1 = new byte[16 + plaintext_1.Length];
        {
            using var aesSiv = new AesSiv(key);
            aesSiv.Encrypt(plaintext_1, ciphertext_1, associatedData_1);
        }

        var associatedData_2 = new byte[][]
        {
            Enumerable.Range(4001, 4).ToUncheckedByteArray(),
        };
        var plaintext_2 = Enumerable.Range(9, 5).ToUncheckedByteArray();
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
                CollectionAssert.AreEqual(ciphertext_1, test);
            }
            {
                var test = new byte[ciphertext_2.Length];
                aesSiv.Encrypt(plaintext_2, test, associatedData_2);
                CollectionAssert.AreEqual(ciphertext_2, test);
            }
            {
                var test = new byte[plaintext_1.Length];
                aesSiv.Decrypt(ciphertext_1, test, associatedData_1);
                CollectionAssert.AreEqual(plaintext_1, test);
            }
            {
                var test = new byte[plaintext_2.Length];
                aesSiv.Decrypt(ciphertext_2, test, associatedData_2);
                CollectionAssert.AreEqual(plaintext_2, test);
            }
        }
    }
}
