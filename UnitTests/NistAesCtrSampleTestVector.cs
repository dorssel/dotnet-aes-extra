// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
// SPDX-FileCopyrightText: 2022 NIST
//
// SPDX-License-Identifier: MIT
// SPDX-License-Identifier: LicenseRef-NIST-OtherDataWorks

using System.Runtime.Serialization;
using System.Text;
using System.Text.RegularExpressions;

namespace UnitTests;

[DataContract]
sealed partial record NistAesCtrSampleTestVector
{
    public static IReadOnlyList<NistAesCtrSampleTestVector> All { get; }

#pragma warning disable IDE1006 // Naming Styles
    [DataMember]
    string _Section { get; init; }
    [DataMember]
    string _Name { get; init; }
    [DataMember]
    byte[] _Key { get; init; }
    [DataMember]
    byte[] _InitialCounter { get; init; }
    [DataMember]
    byte[] _Plaintext { get; init; }
    [DataMember]
    byte[] _Ciphertext { get; init; }
#pragma warning restore IDE1006 // Naming Styles

    public string Section => _Section;
    public string Name => _Name;
    public ReadOnlyMemory<byte> Key => _Key;
    public ReadOnlyMemory<byte> InitialCounter => _InitialCounter;
    public ReadOnlyMemory<byte> Plaintext => _Plaintext;
    public ReadOnlyMemory<byte> Ciphertext => _Ciphertext;

    static readonly char[] lineSeparators = ['\r', '\n'];

    NistAesCtrSampleTestVector(string Section, string Name, string Data)
    {
        _Section = Section;
        _Name = Name;

        var keyHex = new StringBuilder();
        var initialCounterHex = new StringBuilder();
        var plaintextHex = new StringBuilder();
        var ciphertextHex = new StringBuilder();
        foreach (var rawLine in Data.Split(lineSeparators, StringSplitOptions.RemoveEmptyEntries))
        {
            var line = rawLine.Trim();
            var match = EndingHexRegex().Match(line);
            if (match.Success)
            {
                var hex = match.Groups[1].Value;
                if (line.StartsWith("Key") || line == hex)
                {
                    keyHex.Append(hex);
                }
                else if (line.StartsWith("Init. Counter"))
                {
                    initialCounterHex.Append(hex);
                }
                else if (line.StartsWith("Plaintext"))
                {
                    plaintextHex.Append(hex);
                }
                else if (line.StartsWith("Ciphertext"))
                {
                    ciphertextHex.Append(hex);
                }
            }
        }
        _Key = Convert.FromHexString(keyHex.ToString());
        _InitialCounter = Convert.FromHexString(initialCounterHex.ToString());
        _Plaintext = Convert.FromHexString(plaintextHex.ToString());
        _Ciphertext = Convert.FromHexString(ciphertextHex.ToString());
    }

    [GeneratedRegex("([0-9a-fA-F]+)$")]
    private static partial Regex EndingHexRegex();

    static NistAesCtrSampleTestVector()
    {
        // See: NIST SP 800-38A, Appendix F
        // See: https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
        // Licensed under LicenseRef-NIST-OtherDataWorks
        //
        // NOTE: The Encrypt (odd) and Decrypt (even) examples are actually the same.
        // We include only one.
        var testVectors = new List<NistAesCtrSampleTestVector>
        {
            new("F.5.1", "CTR-AES128.Encrypt", @"
                    Key             2B7E151628AED2A6ABF7158809CF4F3C
                    Init. Counter   F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF
                    Block #1
                    Input Block     F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF
                    Output Block    EC8CDF7398607CB0F2D21675EA9EA1E4
                    Plaintext       6BC1BEE22E409F96E93D7E117393172A
                    Ciphertext      874D6191B620E3261BEF6864990DB6CE
                    Block #2
                    Input Block     F0F1F2F3F4F5F6F7F8F9FAFBFCFDFF00
                    Output Block    362B7C3C6773516318A077D7FC5073AE
                    Plaintext       AE2D8A571E03AC9C9EB76FAC45AF8E51
                    Ciphertext      9806F66B7970FDFF8617187BB9FFFDFF
                    Block #3
                    Input Block     F0F1F2F3F4F5F6F7F8F9FAFBFCFDFF01
                    Output Block    6A2CC3787889374FBEB4C81B17BA6C44
                    Plaintext       30C81C46A35CE411E5FBC1191A0A52EF
                    Ciphertext      5AE4DF3EDBD5D35E5B4F09020DB03EAB
                    Block #4
                    Input Block     F0F1F2F3F4F5F6F7F8F9FAFBFCFDFF02
                    Output Block    E89C399FF0F198C6D40A31DB156CABFE
                    Plaintext       F69F2445DF4F9B17AD2B417BE66C3710
                    Ciphertext      1E031DDA2FBE03D1792170A0F3009CEE
                "),

            new("F.5.3", "CTR-AES192.Encrypt", @"
                    Key             8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B
                    Init. Counter   F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF
                    Block #1
                    Input Block     F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF
                    Output Block    717D2DC639128334A6167A488DED7921
                    Plaintext       6BC1BEE22E409F96E93D7E117393172A
                    Ciphertext      1ABC932417521CA24F2B0459FE7E6E0B
                    Block #2
                    Input Block     F0F1F2F3F4F5F6F7F8F9FAFBFCFDFF00
                    Output Block    A72EB3BB14A556734B7BAD6AB16100C5
                    Plaintext       AE2D8A571E03AC9C9EB76FAC45AF8E51
                    Ciphertext      090339EC0AA6FAEFD5CCC2C6F4CE8E94
                    Block #3
                    Input Block     F0F1F2F3F4F5F6F7F8F9FAFBFCFDFF01
                    Output Block    2EFEAE2D72B722613446DC7F4C2AF918
                    Plaintext       30C81C46A35CE411E5FBC1191A0A52EF
                    Ciphertext      1E36B26BD1EBC670D1BD1D665620ABF7
                    Block #4
                    Input Block     F0F1F2F3F4F5F6F7F8F9FAFBFCFDFF02
                    Output Block    B9E783B30DD7924FF7BC9B97BEAA8740
                    Plaintext       F69F2445DF4F9B17AD2B417BE66C3710
                    Ciphertext      4F78A7F6D29809585A97DAEC58C6B050
            "),

            new("F.5.5", "CTR-AES256.Encrypt", @"
                    Key             603DEB1015CA71BE2B73AEF0857D7781
                                    1F352C073B6108D72D9810A30914DFF4
                    Init. Counter   F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF
                    Block #1
                    Input Block     F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF
                    Output Block    0BDF7DF1591716335E9A8B15C860C502
                    Plaintext       6BC1BEE22E409F96E93D7E117393172A
                    Ciphertext      601EC313775789A5B7A7F504BBF3D228
                    Block #2
                    Input Block     F0F1F2F3F4F5F6F7F8F9FAFBFCFDFF00
                    Output Block    5A6E699D536119065433863C8F657B94
                    Plaintext       AE2D8A571E03AC9C9EB76FAC45AF8E51
                    Ciphertext      F443E3CA4D62B59ACA84E990CACAF5C5
                    Block #3
                    Input Block     F0F1F2F3F4F5F6F7F8F9FAFBFCFDFF01
                    Output Block    1BC12C9C01610D5D0D8BD6A3378ECA62
                    Plaintext       30C81C46A35CE411E5FBC1191A0A52EF
                    Ciphertext      2B0930DAA23DE94CE87017BA2D84988D
                    Block #4
                    Input Block     F0F1F2F3F4F5F6F7F8F9FAFBFCFDFF02
                    Output Block    2956E1C8693536B1BEE99C73A31576B6
                    Plaintext       F69F2445DF4F9B17AD2B417BE66C3710
                    Ciphertext      DFC9C58DB67AADA613C2DD08457941A6
            "),

        };
        All = testVectors.AsReadOnly();
    }
}
