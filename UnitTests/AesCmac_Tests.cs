// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace UnitTests;

[TestClass]
sealed class AesCmac_Tests
{
    [TestMethod]
    public void Create()
    {
        using var keyedHashAlgorithm = AesCmac.Create();
        Assert.IsNotNull(keyedHashAlgorithm);
    }

    [TestMethod]
    public void Create_Name()
    {
#pragma warning disable CS0618 // Type or member is obsolete
        using var keyedHashAlgorithm = AesCmac.Create("AesCmac");
#pragma warning restore CS0618 // Type or member is obsolete
        Assert.IsNotNull(keyedHashAlgorithm);
    }

    [TestMethod]
    public void Create_NullNameFails()
    {
        Assert.ThrowsException<ArgumentNullException>(() =>
        {
#pragma warning disable CS0618 // Type or member is obsolete
            using var keyedHashAlgorithm = AesCmac.Create(null!);
#pragma warning restore CS0618 // Type or member is obsolete
        });
    }

    [TestMethod]
    public void Create_OtherNameReturnsNull()
    {
#pragma warning disable CS0618 // Type or member is obsolete
        using var keyedHashAlgorithm = AesCmac.Create("SomeOtherName");
#pragma warning restore CS0618 // Type or member is obsolete
        Assert.IsNull(keyedHashAlgorithm);
    }

    [TestMethod]
    public void Constructor_Default()
    {
        using var aesCmac = new AesCmac();
    }

    [TestMethod]
    [DataRow(128)]
    [DataRow(192)]
    [DataRow(256)]
    public void Constructor_WithKey(int keySize)
    {
        using var aesCmac = new AesCmac(new byte[keySize / 8]);
    }

    [TestMethod]
    public void Constructor_WithInvalidKeySize()
    {
        Assert.ThrowsException<CryptographicException>(() =>
        {
            using var aesCmac = new AesCmac(new byte[42]);
        });
    }

    [TestMethod]
    public void Constructor_WithNullKey()
    {
        Assert.ThrowsException<ArgumentNullException>(() =>
        {
            using var aesCmac = new AesCmac(null!);
        });
    }

    [TestMethod]
    public void Dispose()
    {
        var aesCmac = new AesCmac();
        aesCmac.Dispose();
    }

    [TestMethod]
    public void Dispose_Double()
    {
        var aesCmac = new AesCmac();
        aesCmac.Dispose();
        aesCmac.Dispose();
    }

    [TestMethod]
    public void Key_Change()
    {
        var keys = NistAesCmacSampleTestVector.All
            .Select(tv => tv.Key.ToArray())
            .DistinctBy(BitConverter.ToString);

        using var aesCmac = new AesCmac();
        foreach (var key in keys)
        {
            aesCmac.Key = key;
            CollectionAssert.AreEqual(key, aesCmac.Key);
        }
    }

    [TestMethod]
    public void ComputeHash_Segmented()
    {
        var testVector = NistAesCmacSampleTestVector.All.First(tv => tv.PT.Length == 64);

        using var aesCmac = new AesCmac(testVector.Key.ToArray());

        var pos = 0;
        void Transfer(int count)
        {
            aesCmac.TransformBlock(testVector.PT.ToArray(), pos, count, null, 0);
            pos += count;
        }

        // less than 1 block
        Transfer(16 - 3);
        // append to, but don't complete the partial block
        Transfer(2);
        // complete the partial block precisely
        Transfer(1);
        // more than 1 block, but not an exact multiple
        Transfer((2 * 16) - 3);
        // topping off the partial block + again less than 1 block
        Transfer(16);
        // remainder
        Transfer(testVector.PT.Length - pos);

        aesCmac.TransformFinalBlock([], 0, 0);

        CollectionAssert.AreEqual(testVector.Tag.ToArray(), aesCmac.Hash);
    }

    [TestMethod]
    public void ComputeHash_Reuse()
    {
        using var aesCmac = new AesCmac();
        foreach (var testVector in NistAesCmacSampleTestVector.All)
        {
            aesCmac.Key = testVector.Key.ToArray();
            var tag = aesCmac.ComputeHash(testVector.PT.ToArray());
            CollectionAssert.AreEqual(testVector.Tag.ToArray(), tag);
        }
    }
}
