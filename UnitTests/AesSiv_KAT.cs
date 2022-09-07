// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace UnitTests;

[TestClass]
sealed class AesSiv_KAT
{
    const int BLOCKSIZE = 16; // bytes

    [TestMethod]
    [TestCategory("RFC")]
    [RfcAesSivTestVectorSource]
    public void Rfc_Encrypt(RfcAesSivTestVector testVector)
    {
        using var aesSiv = new AesSiv(testVector.Key.ToArray());
        var associatedData = new List<byte[]>(testVector.AD.Select(ad => ad.ToArray()));
        if (testVector.Nonce.HasValue)
        {
            associatedData.Add(testVector.Nonce.Value.ToArray());
        }
        var ciphertext = new byte[BLOCKSIZE + testVector.Plaintext.Length];
        aesSiv.Encrypt(testVector.Plaintext.ToArray(), ciphertext, associatedData.ToArray());
        Assert.IsTrue(Enumerable.SequenceEqual(testVector.output.ToArray(), ciphertext));
    }

    [TestMethod]
    [TestCategory("RFC")]
    [RfcAesSivTestVectorSource]
    public void Rfc_Decrypt(RfcAesSivTestVector testVector)
    {
        using var aesSiv = new AesSiv(testVector.Key.ToArray());
        var associatedData = new List<byte[]>(testVector.AD.Select(ad => ad.ToArray()));
        if (testVector.Nonce.HasValue)
        {
            associatedData.Add(testVector.Nonce.Value.ToArray());
        }
        var plaintext = new byte[testVector.output.Length - BLOCKSIZE];
        aesSiv.Decrypt(testVector.output.ToArray(), plaintext, associatedData.ToArray());
        Assert.IsTrue(Enumerable.SequenceEqual(testVector.Plaintext.ToArray(), plaintext));
    }
}
