// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace UnitTests;

static class ExtensionMethods
{
    public static byte[] ToUncheckedByteArray(this IEnumerable<int> integers)
    {
        return [.. integers.Select(i => unchecked((byte)i))];
    }
}
