// SPDX-FileCopyrightText: 2025 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace UnitTests;

[TestClass]
sealed class AesCmacPrf128_KAT
{
    [TestMethod]
    [TestCategory("RFC")]
    [RfcAesCmacPrf128TestVectorSource]
    public void Rfc_DeriveKey_Array_Array(RfcAesCmacPrf128TestVector testVector)
    {
        var output = AesCmacPrf128.DeriveKey(testVector.Key.ToArray(), testVector.Message.ToArray());
        CollectionAssert.AreEqual(testVector.Output.ToArray(), output);
    }

    [TestMethod]
    [TestCategory("RFC")]
    [RfcAesCmacPrf128TestVectorSource]
    public void Rfc_DeriveKey_ReadOnlySpan_ReadOnlySpan_Span(RfcAesCmacPrf128TestVector testVector)
    {
        var output = new byte[testVector.Output.Length];
        int bytesWritten = AesCmacPrf128.DeriveKey(testVector.Key.Span, testVector.Message.Span, output);
        Assert.AreEqual(bytesWritten, testVector.Output.Length);
        CollectionAssert.AreEqual(testVector.Output.ToArray(), output);
    }
}
