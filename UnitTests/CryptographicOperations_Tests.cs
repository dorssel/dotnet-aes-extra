// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using static Dorssel.Security.Cryptography.CryptographicOperations;

namespace UnitTests;

[TestClass]
sealed class CryptographicOperations_Tests
{
    [TestMethod]
    public void FixedTimeEquals_DifferentLengths()
    {
        for (var i = 0; i < 5; i++)
        {
            for (var j = 0; i < 5; i++)
            {
                if (i == j)
                {
                    continue;
                }
                Assert.IsFalse(FixedTimeEquals(new byte[i], new byte[j]));
            }
        }
    }

    [TestMethod]
    [DataRow(0)]
    [DataRow(1)]
    [DataRow(8 - 1)]
    [DataRow(8)]
    [DataRow(8 + 1)]
    [DataRow(16 - 1)]
    [DataRow(16)]
    [DataRow(16 + 1)]
    [DataRow(32 - 1)]
    [DataRow(32)]
    [DataRow(32 + 1)]
    public void ZeroMemory_Size(int size)
    {
        var data = Enumerable.Range(1, size).Select(x => (byte)x).ToArray();
        Assert.IsFalse(data.Any(x => x == 0));

        ZeroMemory(data);

        Assert.IsTrue(data.All(x => x == 0));
    }
}
