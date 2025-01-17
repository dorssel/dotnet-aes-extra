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
        // See: RFC 4615, Section 4
        // Licensed under LicenseRef-IETF-Trust
        var testVectors = new List<RfcAesCmacPrf128TestVector>
        {
            new("Key Length 18", @"
                    00010203 04050607 08090A0B 0C0D0E0F EDCB
                ", @"
                    00010203 04050607 08090A0B 0C0D0E0F 10111213
                ", @"
                    84A348A4 A45D235B ABFFFC0D 2B4DA09A
                "
            ),

            new("Key Length 16", @"
                    00010203 04050607 08090A0B 0C0D0E0F
                ", @"
                    00010203 04050607 08090A0B 0C0D0E0F 10111213
                ", @"
                    980AE87B 5F4C9C52 14F5B6A8 455E4C2D
                "
            ),

            new("Key Length 10", @"
                    00010203 04050607 0809
                ", @"
                    00010203 04050607 08090A0B 0C0D0E0F 10111213
                ", @"
                    290D9E11 2EDB09EE 141FCF64 C0B72F3D
                "
            ),
        };
        All = testVectors.AsReadOnly();
    }
}
