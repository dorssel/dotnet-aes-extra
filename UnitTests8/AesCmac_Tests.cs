// SPDX-FileCopyrightText: 2025 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography;

namespace UnitTests8;

[TestClass]
sealed class AesCmac_Tests
{
    const int BLOCKSIZE = 16;  // bytes

    [TestMethod]
    public void TryComputeHash()
    {
        using var aesCmac = new AesCmac();
        aesCmac.TryComputeHash([1, 2, 3], new byte[BLOCKSIZE], out _);
    }
}
