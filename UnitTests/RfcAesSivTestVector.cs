// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
// SPDX-FileCopyrightText: 2008 Dan Harkins
//
// SPDX-License-Identifier: MIT
// SPDX-License-Identifier: LicenseRef-IETF-Trust

using System.Collections.ObjectModel;
using System.Text.RegularExpressions;

namespace UnitTests;

public record RfcAesSivTestVector
{
    public static IReadOnlyList<RfcAesSivTestVector> All { get; }

    static byte[] FromHexString(string hexWithWhiteSpace)
    {
        return Convert.FromHexString(Regex.Replace(hexWithWhiteSpace, @"\s+", ""));
    }

    public string Name { get; }
    public ReadOnlyMemory<byte> Key { get; }
    public ReadOnlyCollection<ReadOnlyMemory<byte>> AD { get; }
    public ReadOnlyMemory<byte>? Nonce { get; }
    public ReadOnlyMemory<byte> Plaintext { get; }
    public ReadOnlyMemory<byte> output { get; }

    RfcAesSivTestVector(string Name, string Key, string[] AD, string? Nonce, string Plaintext, string output)
    {
        this.Name = Name;
        this.Key = FromHexString(Key);
        {
            var associatedData = new ReadOnlyMemory<byte>[AD.Length];
            for (var i = 0; i < AD.Length; i++)
            {
                associatedData[i] = FromHexString(AD[i]);
            }
            this.AD = new(associatedData);
        }
        if (Nonce is not null)
        {
            this.Nonce = FromHexString(Nonce);
        }
        this.Plaintext = FromHexString(Plaintext);
        this.output = FromHexString(output);
    }

    static RfcAesSivTestVector()
    {
        // See: RFC 5297, Appendix A
        // Licenced under LicenseRef-IETF-Trust
        var testVectors = new List<RfcAesSivTestVector>
        {
            // cspell:disable
            new("Deterministic", @"
                    fffefdfc fbfaf9f8 f7f6f5f4 f3f2f1f0
                    f0f1f2f3 f4f5f6f7 f8f9fafb fcfdfeff
                ", new string[] { @"
                        10111213 14151617 18191a1b 1c1d1e1f
                        20212223 24252627
                " },
                null
                , @"
                    11223344 55667788 99aabbcc ddee
                ", @"
                    85632d07 c6e8f37f 950acd32 0a2ecc93
                    40c02b96 90c4dc04 daef7f6a fe5c
                "
            ),

            new("Nonce-Based", @"
                    7f7e7d7c 7b7a7978 77767574 73727170
                    40414243 44454647 48494a4b 4c4d4e4f
                ", new string[] { @"
                        00112233 44556677 8899aabb ccddeeff
                        deaddada deaddada ffeeddcc bbaa9988
                        77665544 33221100
                    ", @"
                        10203040 50607080 90a0
                " }, @"
                    09f91102 9d74e35b d84156c5 635688c0
                ", @"
                    74686973 20697320 736f6d65 20706c61
                    696e7465 78742074 6f20656e 63727970
                    74207573 696e6720 5349562d 414553
                ", @"
                    7bdb6e3b 432667eb 06f4d14b ff2fbd0f
                    cb900f2f ddbe4043 26601965 c889bf17
                    dba77ceb 094fa663 b7a3f748 ba8af829
                    ea64ad54 4a272e9c 485b62a3 fd5c0d
                "
            ),

            // cspell:enable
        };
        All = testVectors.AsReadOnly();
    }
}
