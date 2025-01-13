// SPDX-FileCopyrightText: 2025 Frans van Dorsselaer
// SPDX-FileCopyrightText: 2006 The Internet Society
//
// SPDX-License-Identifier: MIT
// SPDX-License-Identifier: LicenseRef-IETF-Trust

using System.Runtime.Serialization;
using System.Text.RegularExpressions;

namespace UnitTests;

[DataContract]
sealed partial record RfcAesCmacPrf128TestVector
{
    public static IReadOnlyList<RfcAesCmacPrf128TestVector> All { get; }

    [GeneratedRegex(@"\s+")]
    private static partial Regex WhitespaceRegex();

    static byte[] FromHexString(string hexWithWhiteSpace)
    {
        return Convert.FromHexString(WhitespaceRegex().Replace(hexWithWhiteSpace, ""));
    }

#pragma warning disable IDE1006 // Naming Styles
    [DataMember]
    string _Name { get; init; }
    [DataMember]
    byte[] _Key { get; init; }
    [DataMember]
    byte[] _Message { get; init; }
    [DataMember]
    byte[] _Output { get; init; }
#pragma warning restore IDE1006 // Naming Styles

    public string Name => _Name;
    public ReadOnlyMemory<byte> Key => _Key;
    public ReadOnlyMemory<byte> Message => _Message;
    public ReadOnlyMemory<byte> Output => _Output;

    RfcAesCmacPrf128TestVector(string Name, string Key, string Message, string Output)
    {
        _Name = Name;
        _Key = FromHexString(Key);
        _Message = FromHexString(Message);
        _Output = FromHexString(Output);
    }

    static RfcAesCmacPrf128TestVector()
    {
        // See: RFC 5297, Appendix A
        // Licensed under LicenseRef-IETF-Trust
        var testVectors = new List<RfcAesCmacPrf128TestVector>
        {
            new("Key Length 18", @"
                    00010203 04050607 08090a0b 0c0d0e0f edcb
                ", @"
                    00010203 04050607 08090a0b 0c0d0e0f 10111213
                ", @"
                    84a348a4 a45d235b abfffc0d 2b4da09a
                "
            ),

            new("Key Length 16", @"
                    00010203 04050607 08090a0b 0c0d0e0f
                ", @"
                    00010203 04050607 08090a0b 0c0d0e0f 10111213
                ", @"
                    980ae87b 5f4c9c52 14f5b6a8 455e4c2d
                "
            ),

            new("Key Length 10", @"
                    00010203 04050607 0809
                ", @"
                    00010203 04050607 08090a0b 0c0d0e0f 10111213
                ", @"
                    290d9e11 2edb09ee 141fcf64 c0b72f3d
                "
            ),
        };
        All = testVectors.AsReadOnly();
    }
}
