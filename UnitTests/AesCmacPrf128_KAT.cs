// SPDX-FileCopyrightText: 2025 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Text;

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
        AesCmacPrf128.DeriveKey(testVector.Key.Span, testVector.Message.Span, output);
        CollectionAssert.AreEqual(testVector.Output.ToArray(), output);
    }

    [TestMethod]
    [TestCategory("MbedTLS")]
    [MbedTlsPbkdf2AesCmacPrf128TestVectorSource]
    public void Pbkdf2_Array_Array(MbedTlsPbkdf2AesCmacPrf128TestVector testVector)
    {
        var output = AesCmacPrf128.Pbkdf2(testVector.Password.ToArray(), testVector.Salt.ToArray(), testVector.Iterations, testVector.Output.Length);

        CollectionAssert.AreEqual(testVector.Output.ToArray(), output);
    }

    [TestMethod]
    [TestCategory("MbedTLS")]
    [MbedTlsPbkdf2AesCmacPrf128TestVectorSource]
    public void Pbkdf2_ReadOnlyBytes_ReadOnlySpan(MbedTlsPbkdf2AesCmacPrf128TestVector testVector)
    {
        var output = AesCmacPrf128.Pbkdf2(testVector.Password.Span, testVector.Salt.Span, testVector.Iterations, testVector.Output.Length);

        CollectionAssert.AreEqual(testVector.Output.ToArray(), output);
    }

    [TestMethod]
    [TestCategory("MbedTLS")]
    [MbedTlsPbkdf2AesCmacPrf128TestVectorSource]
    public void Pbkdf2_ReadOnlyBytes_ReadOnlySpan_Span(MbedTlsPbkdf2AesCmacPrf128TestVector testVector)
    {
        var output = new byte[testVector.Output.Length];
        AesCmacPrf128.Pbkdf2(testVector.Password.Span, testVector.Salt.Span, output, testVector.Iterations);

        CollectionAssert.AreEqual(testVector.Output.ToArray(), output);
    }

    [TestMethod]
    [TestCategory("MbedTLS")]
    [MbedTlsPbkdf2AesCmacPrf128TestVectorSource]
    public void Pbkdf2_string_Array(MbedTlsPbkdf2AesCmacPrf128TestVector testVector)
    {
        var output = AesCmacPrf128.Pbkdf2(Encoding.UTF8.GetString(testVector.Password.Span), testVector.Salt.ToArray(), testVector.Iterations,
            testVector.Output.Length);

        CollectionAssert.AreEqual(testVector.Output.ToArray(), output);
    }

    [TestMethod]
    [TestCategory("MbedTLS")]
    [MbedTlsPbkdf2AesCmacPrf128TestVectorSource]
    public void Pbkdf2_ReadOnlyChars_ReadOnlySpan(MbedTlsPbkdf2AesCmacPrf128TestVector testVector)
    {
        var output = AesCmacPrf128.Pbkdf2(Encoding.UTF8.GetString(testVector.Password.Span).AsSpan(), testVector.Salt.Span, testVector.Iterations,
            testVector.Output.Length);

        CollectionAssert.AreEqual(testVector.Output.ToArray(), output);
    }

    [TestMethod]
    [TestCategory("MbedTLS")]
    [MbedTlsPbkdf2AesCmacPrf128TestVectorSource]
    public void Pbkdf2_ReadOnlyChars_ReadOnlySpan_Span(MbedTlsPbkdf2AesCmacPrf128TestVector testVector)
    {
        var output = new byte[testVector.Output.Length];
        AesCmacPrf128.Pbkdf2(Encoding.UTF8.GetString(testVector.Password.Span).AsSpan(), testVector.Salt.Span, output, testVector.Iterations);

        CollectionAssert.AreEqual(testVector.Output.ToArray(), output);
    }
}
