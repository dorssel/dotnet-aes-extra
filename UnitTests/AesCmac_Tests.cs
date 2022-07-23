// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Diagnostics;
using System.IO.Pipelines;

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
        using var keyedHashAlgorithm = AesCmac.Create("AesCmac");
        Assert.IsNotNull(keyedHashAlgorithm);
    }

    [TestMethod]
    public void Create_NullNameFails()
    {
        Assert.ThrowsException<ArgumentNullException>(() =>
        {
            using var keyedHashAlgorithm = AesCmac.Create(null!);
        });
    }

    [TestMethod]
    public void Create_OtherNameReturnsNull()
    {
        using var keyedHashAlgorithm = AesCmac.Create("SomeOtherName");
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
            .DistinctBy(key => BitConverter.ToString(key));

        using var aesCmac = new AesCmac();
        foreach (var key in keys)
        {
            aesCmac.Key = key;
            Assert.IsTrue(Enumerable.SequenceEqual(key, aesCmac.Key));
        }
    }

    [TestMethod]
    public void ComputeHash_Segmented()
    {
        var testVector = NistAesCmacSampleTestVector.All.First(tv => tv.PT.Length == 64);

        using var aesCmac = new AesCmac(testVector.Key.ToArray());

        var pos = 0;
        var Transfer = (int count) =>
        {
            aesCmac.TransformBlock(testVector.PT.ToArray(), pos, count, null, 0);
            pos += count;
        };

        // less than 1 block
        Transfer(16 - 3);
        // append to, but don't complete the partial block
        Transfer(2);
        // complete the partial block precisely
        Transfer(1);
        // more than 1 block, but not an exact multiple
        Transfer(2 * 16 - 3);
        // topping off the partial block + again less than 1 block
        Transfer(16);
        // remainder
        Transfer(testVector.PT.Length - pos);

        aesCmac.TransformFinalBlock(Array.Empty<byte>(), 0, 0);

        Assert.IsTrue(Enumerable.SequenceEqual(testVector.Tag.ToArray(), aesCmac.Hash!));
    }

    [TestMethod]
    public void ComputeHash_Reuse()
    {
        using var aesCmac = new AesCmac();
        foreach (var testVector in NistAesCmacSampleTestVector.All)
        {
            aesCmac.Key = testVector.Key.ToArray();
            var tag = aesCmac.ComputeHash(testVector.PT.ToArray());
            Assert.IsTrue(Enumerable.SequenceEqual(testVector.Tag.ToArray(), tag));
        }
    }
}
