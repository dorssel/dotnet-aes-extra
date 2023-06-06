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
    public void NistExample(NistAesCmacSampleTestVector testVector)
    {
        using var aesCmac = AesCmac.Create();
        aesCmac.Key = testVector.Key.ToArray();
        var tag = aesCmac.ComputeHash(testVector.PT.ToArray());
        CollectionAssert.AreEqual(testVector.Tag.ToArray(), tag);
    }
}
