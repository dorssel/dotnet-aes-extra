// SPDX-FileCopyrightText: 2026 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using FsCheck;
using FsCheck.Fluent;

namespace FuzzingTests;

[TestClass]
sealed class AesCmac_Tests
{
    [TestMethod]
    public void FuzzingSomething()
    {
        using var aesCmac = new AesCmac();

        Prop.ForAll<byte[]>(bytes => aesCmac.ComputeHash(bytes).Length == 16).QuickCheckThrowOnFailure();
    }
}
