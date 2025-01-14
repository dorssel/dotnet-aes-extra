// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
// SPDX-FileCopyrightText: 2008 Dan Harkins
//
// SPDX-License-Identifier: MIT
// SPDX-License-Identifier: LicenseRef-IETF-Trust

using System.Collections.ObjectModel;
using System.Runtime.Serialization;
using System.Text.RegularExpressions;

namespace UnitTests;

[DataContract]
sealed partial record RfcAesSivTestVector
{
    public static IReadOnlyList<RfcAesSivTestVector> All { get; }

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
    byte[][] _AD { get; init; }
    [DataMember]
    byte[]? _Nonce { get; init; }
    [DataMember]
    byte[] _Plaintext { get; init; }
    [DataMember]
    byte[] _output { get; init; }
#pragma warning restore IDE1006 // Naming Styles

    public string Name => _Name;
    public ReadOnlyMemory<byte> Key => _Key;
    public ReadOnlyCollection<ReadOnlyMemory<byte>> AD => new((from item in _AD select (ReadOnlyMemory<byte>)item.AsMemory()).ToList());
    public ReadOnlyMemory<byte>? Nonce => _Nonce is null ? null : (ReadOnlyMemory<byte>?)_Nonce.AsMemory();
    public ReadOnlyMemory<byte> Plaintext => _Plaintext;
#pragma warning disable IDE1006 // Naming Styles
    public ReadOnlyMemory<byte> output => _output;
#pragma warning restore IDE1006 // Naming Styles

    RfcAesSivTestVector(string Name, string Key, string[] AD, string? Nonce, string Plaintext, string output)
    {
        _Name = Name;
        _Key = FromHexString(Key);
        {
            var associatedData = new byte[AD.Length][];
            for (var i = 0; i < AD.Length; i++)
            {
                associatedData[i] = FromHexString(AD[i]);
            }
            _AD = associatedData;
        }
        if (Nonce is not null)
        {
            _Nonce = FromHexString(Nonce);
        }
        _Plaintext = FromHexString(Plaintext);
        _output = FromHexString(output);
    }

    static RfcAesSivTestVector()
    {
        // See: RFC 5297, Appendix A
        // Licensed under LicenseRef-IETF-Trust
        var testVectors = new List<RfcAesSivTestVector>
        {
            new("Deterministic", @"
                    FFFEFDFC FBFAF9F8 F7F6F5F4 F3F2F1F0
                    F0F1F2F3 F4F5F6F7 F8F9FAFB FCFDFEFF
                ", [ @"
                        10111213 14151617 18191A1B 1C1D1E1F
                        20212223 24252627
                " ],
                null
                , @"
                    11223344 55667788 99AABBCC DDEE
                ", @"
                    85632D07 C6E8F37F 950ACD32 0A2ECC93
                    40C02B96 90C4DC04 DAEF7F6A FE5C
                "
            ),

            new("Nonce-Based", @"
                    7F7E7D7C 7B7A7978 77767574 73727170
                    40414243 44454647 48494A4B 4C4D4E4F
                ", [ @"
                        00112233 44556677 8899AABB CCDDEEFF
                        DEADDADA DEADDADA FFEEDDCC BBAA9988
                        77665544 33221100
                    ", @"
                        10203040 50607080 90A0
                " ], @"
                    09F91102 9D74E35B D84156C5 635688C0
                ", @"
                    74686973 20697320 736F6D65 20706C61
                    696E7465 78742074 6F20656E 63727970
                    74207573 696E6720 5349562D 414553
                ", @"
                    7BDB6E3B 432667EB 06F4D14B FF2FBD0F
                    CB900F2F DDBE4043 26601965 C889BF17
                    DBA77CEB 094FA663 B7A3F748 BA8AF829
                    EA64AD54 4A272E9C 485B62A3 FD5C0D
                "
            ),
        };
        All = testVectors.AsReadOnly();
    }
}
