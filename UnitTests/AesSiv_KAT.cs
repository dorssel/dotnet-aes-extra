// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace UnitTests;

[TestClass]
sealed class AesSiv_KAT
{
    [TestMethod]
    [TestCategory("RFC")]
    [RfcAesSivTestVectorSource]
    public void Rfc_Encrypt_Array_Array_Array(RfcAesSivTestVector testVector)
    {
        using var aesSiv = new AesSiv(testVector.Key.ToArray());
        var associatedData = new List<byte[]>(testVector.AD.Select(ad => ad.ToArray()));
        if (testVector.Nonce.HasValue)
        {
            associatedData.Add(testVector.Nonce.Value.ToArray());
        }
        var ciphertext = new byte[testVector.output.Length];
        aesSiv.Encrypt(testVector.Plaintext.ToArray(), ciphertext, [.. associatedData]);
        Assert.AreSequenceEqual(testVector.output.ToArray(), ciphertext);
    }

    [TestMethod]
    [TestCategory("RFC")]
    [RfcAesSivTestVectorSource(true)]
    public void Rfc_Encrypt_ReadOnlySpan_Span_ReadOnlySpan(RfcAesSivTestVector testVector)
    {
        using var aesSiv = new AesSiv(testVector.Key.ToArray());
        var associatedData = testVector.Nonce ?? testVector.AD.Single();
        var ciphertext = new byte[testVector.output.Length];
        aesSiv.Encrypt(testVector.Plaintext.Span, ciphertext.AsSpan(), associatedData.Span);
        Assert.AreSequenceEqual(testVector.output.ToArray(), ciphertext);
    }

    [TestMethod]
    [TestCategory("RFC")]
    [RfcAesSivTestVectorSource]
    public void Rfc_Encrypt_ReadOnlySpan_Span_ReadOnlyMemories(RfcAesSivTestVector testVector)
    {
        using var aesSiv = new AesSiv(testVector.Key.ToArray());
        var associatedData = new List<ReadOnlyMemory<byte>>(testVector.AD);
        if (testVector.Nonce.HasValue)
        {
            associatedData.Add(testVector.Nonce.Value);
        }
        var ciphertext = new byte[testVector.output.Length];
        aesSiv.Encrypt(testVector.Plaintext.Span, ciphertext.AsSpan(), associatedData.ToArray().AsSpan());
        Assert.AreSequenceEqual(testVector.output.ToArray(), ciphertext);
    }

    [TestMethod]
    [TestCategory("RFC")]
    [RfcAesSivTestVectorSource]
    public void Rfc_Decrypt_Array_Array_Array(RfcAesSivTestVector testVector)
    {
        using var aesSiv = new AesSiv(testVector.Key.ToArray());
        var associatedData = new List<byte[]>(testVector.AD.Select(ad => ad.ToArray()));
        if (testVector.Nonce.HasValue)
        {
            associatedData.Add(testVector.Nonce.Value.ToArray());
        }
        var plaintext = new byte[testVector.Plaintext.Length];
        aesSiv.Decrypt(testVector.output.ToArray(), plaintext, [.. associatedData]);
        Assert.AreSequenceEqual(testVector.Plaintext.ToArray(), plaintext);
    }

    [TestMethod]
    [TestCategory("RFC")]
    [RfcAesSivTestVectorSource(true)]
    public void Rfc_Decrypt_ReadOnlySpan_Span_ReadOnlySpan(RfcAesSivTestVector testVector)
    {
        using var aesSiv = new AesSiv(testVector.Key.ToArray());
        var associatedData = testVector.Nonce ?? testVector.AD.Single();
        var plaintext = new byte[testVector.Plaintext.Length];
        aesSiv.Decrypt(testVector.output.Span, plaintext.AsSpan(), associatedData.Span);
        Assert.AreSequenceEqual(testVector.Plaintext.ToArray(), plaintext);
    }

    [TestMethod]
    [TestCategory("RFC")]
    [RfcAesSivTestVectorSource]
    public void Rfc_Decrypt_ReadOnlySpan_Span_ReadOnlyMemories(RfcAesSivTestVector testVector)
    {
        using var aesSiv = new AesSiv(testVector.Key.ToArray());
        var associatedData = new List<ReadOnlyMemory<byte>>(testVector.AD);
        if (testVector.Nonce.HasValue)
        {
            associatedData.Add(testVector.Nonce.Value);
        }
        var plaintext = new byte[testVector.Plaintext.Length];
        aesSiv.Decrypt(testVector.output.Span, plaintext.AsSpan(), associatedData.ToArray().AsSpan());
        Assert.AreSequenceEqual(testVector.Plaintext.ToArray(), plaintext);
    }
}
