// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace UnitTests;

[TestClass]
sealed class AesCmac_KAT
{
    [TestMethod]
    [TestCategory("NIST")]
    [NistAesCmacSampleDataSource]
    public void NistExample_ComputeHash(NistAesCmacSampleTestVector testVector)
    {
        using var aesCmac = AesCmac.Create();
        aesCmac.Key = testVector.Key.ToArray();
        var tag = aesCmac.ComputeHash(testVector.PT.ToArray());
        CollectionAssert.AreEqual(testVector.Tag.ToArray(), tag);
    }

    [TestMethod]
    [TestCategory("NIST")]
    [NistAesCmacSampleDataSource]
    public void NistExample_TryHashData(NistAesCmacSampleTestVector testVector)
    {
        var tag = new byte[testVector.Tag.Length];

        var success = AesCmac.TryHashData(testVector.Key.Span, testVector.PT.Span, tag, out var bytesWritten);

        Assert.IsTrue(success);
        Assert.AreEqual(testVector.Tag.Length, bytesWritten);
        CollectionAssert.AreEqual(testVector.Tag.ToArray(), tag);
    }

    [TestMethod]
    [TestCategory("NIST")]
    [NistAesCmacSampleDataSource]
    public void NistExample_HashData_Array_Array(NistAesCmacSampleTestVector testVector)
    {
        var tag = AesCmac.HashData(testVector.Key.ToArray(), testVector.PT.ToArray());

        CollectionAssert.AreEqual(testVector.Tag.ToArray(), tag);
    }

    [TestMethod]
    [TestCategory("NIST")]
    [NistAesCmacSampleDataSource]
    public void NistExample_HashData_ReadOnlySpan_ReadOnlySpan(NistAesCmacSampleTestVector testVector)
    {
        var tag = AesCmac.HashData(testVector.Key.Span, testVector.PT.Span);

        CollectionAssert.AreEqual(testVector.Tag.ToArray(), tag);
    }

    [TestMethod]
    [TestCategory("NIST")]
    [NistAesCmacSampleDataSource]
    public void NistExample_HashData_ReadOnlySpan_ReadOnlySpan_Span(NistAesCmacSampleTestVector testVector)
    {
        var tag = new byte[testVector.Tag.Length];

        var bytesWritten = AesCmac.HashData(testVector.Key.Span, testVector.PT.Span, tag);

        Assert.AreEqual(testVector.Tag.Length, bytesWritten);
        CollectionAssert.AreEqual(testVector.Tag.ToArray(), tag);
    }

    [TestMethod]
    [TestCategory("NIST")]
    [NistAesCmacSampleDataSource]
    public void NistExample_HashData_Array_Stream(NistAesCmacSampleTestVector testVector)
    {
        using var stream = new MemoryStream(testVector.PT.ToArray());

        var tag = AesCmac.HashData(testVector.Key.ToArray(), stream);

        CollectionAssert.AreEqual(testVector.Tag.ToArray(), tag);
    }

    [TestMethod]
    [TestCategory("NIST")]
    [NistAesCmacSampleDataSource]
    public void NistExample_HashData_ReadOnlySpan_Stream(NistAesCmacSampleTestVector testVector)
    {
        using var stream = new MemoryStream(testVector.PT.ToArray());

        var tag = AesCmac.HashData(testVector.Key.Span, stream);

        CollectionAssert.AreEqual(testVector.Tag.ToArray(), tag);
    }

    [TestMethod]
    [TestCategory("NIST")]
    [NistAesCmacSampleDataSource]
    public void NistExample_HashData_ReadOnlySpan_Stream_Span(NistAesCmacSampleTestVector testVector)
    {
        using var stream = new MemoryStream(testVector.PT.ToArray());
        var tag = new byte[testVector.Tag.Length];

        var bytesWritten = AesCmac.HashData(testVector.Key.Span, stream, tag);

        Assert.AreEqual(testVector.Tag.Length, bytesWritten);
        CollectionAssert.AreEqual(testVector.Tag.ToArray(), tag);
    }

    [TestMethod]
    [TestCategory("NIST")]
    [NistAesCmacSampleDataSource]
    public async Task NistExample_HashDataAsync_Array_Stream(NistAesCmacSampleTestVector testVector)
    {
        using var stream = new MemoryStream(testVector.PT.ToArray());

        var tag = await AesCmac.HashDataAsync(testVector.Key.ToArray(), stream);

        CollectionAssert.AreEqual(testVector.Tag.ToArray(), tag);
    }

    [TestMethod]
    [TestCategory("NIST")]
    [NistAesCmacSampleDataSource]
    public async Task NistExample_HashDataAsync_ReadOnlyMemory_Stream(NistAesCmacSampleTestVector testVector)
    {
        using var stream = new MemoryStream(testVector.PT.ToArray());

        var tag = await AesCmac.HashDataAsync(testVector.Key, stream);

        CollectionAssert.AreEqual(testVector.Tag.ToArray(), tag);
    }

    [TestMethod]
    [TestCategory("NIST")]
    [NistAesCmacSampleDataSource]
    public async Task NistExample_HashDataAsync_ReadOnlyMemory_Stream_Memory(NistAesCmacSampleTestVector testVector)
    {
        using var stream = new MemoryStream(testVector.PT.ToArray());
        var tag = new byte[testVector.Tag.Length];

        var bytesWritten = await AesCmac.HashDataAsync(testVector.Key, stream, tag);

        Assert.AreEqual(testVector.Tag.Length, bytesWritten);
        CollectionAssert.AreEqual(testVector.Tag.ToArray(), tag);
    }
}
