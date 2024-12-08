// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
// SPDX-FileCopyrightText: 2022 NIST
//
// SPDX-License-Identifier: MIT
// SPDX-License-Identifier: LicenseRef-NIST-OtherDataWorks

using System.Runtime.Serialization;
using System.Text.RegularExpressions;

namespace UnitTests;

[DataContract]
sealed partial record NistAesCmacSampleTestVector
{
    public static IReadOnlyList<NistAesCmacSampleTestVector> All { get; }

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
    byte[] _PT { get; init; }
    [DataMember]
    byte[] _Tag { get; init; }
#pragma warning restore IDE1006 // Naming Styles

    public string Name => _Name;
    public ReadOnlyMemory<byte> Key => _Key;
    public ReadOnlyMemory<byte> PT => _PT;
    public ReadOnlyMemory<byte> Tag => _Tag;

    NistAesCmacSampleTestVector(string Name, string Key, string PT, string Tag)
    {
        _Name = Name;
        _Key = FromHexString(Key);
        _PT = FromHexString(PT);
        _Tag = FromHexString(Tag);
    }

    static NistAesCmacSampleTestVector()
    {
        // See: https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
        // Licenced under LicenseRef-NIST-OtherDataWorks
        var testVectors = new List<NistAesCmacSampleTestVector>
        {
            new("CMAC-AES128 #1", @"
                    2B7E1516 28AED2A6 ABF71588 09CF4F3C
                ", @"

                ", @"
                    BB1D6929 E9593728 7FA37D12 9B756746
                "),

            new("CMAC-AES128 #2", @"
                    2B7E1516 28AED2A6 ABF71588 09CF4F3C
                ", @"
                    6BC1BEE2 2E409F96 E93D7E11 7393172A
                ", @"
                    070A16B4 6B4D4144 F79BDD9D D04A287C
                "),

            new("CMAC-AES128 #3", @"
                    2B7E1516 28AED2A6 ABF71588 09CF4F3C
                ", @"
                    6BC1BEE2 2E409F96 E93D7E11 7393172A
                    AE2D8A57
                ", @"
                    7D85449E A6EA19C8 23A7BF78 837DFADE
                "),

            new("CMAC-AES128 #4", @"
                    2B7E1516 28AED2A6 ABF71588 09CF4F3C
                ", @"
                    6BC1BEE2 2E409F96 E93D7E11 7393172A
                    AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51
                    30C81C46 A35CE411 E5FBC119 1A0A52EF
                    F69F2445 DF4F9B17 AD2B417B E66C3710
                ", @"
                    51F0BEBF 7E3B9D92 FC497417 79363CFE
                "),

            new("CMAC-AES192 #1", @"
                    8E73B0F7 DA0E6452 C810F32B 809079E5
                    62F8EAD2 522C6B7B
                ", @"

                ", @"
                    D17DDF46 ADAACDE5 31CAC483 DE7A9367
                "),

            new("CMAC-AES192 #2", @"
                    8E73B0F7 DA0E6452 C810F32B 809079E5
                    62F8EAD2 522C6B7B
                ", @"
                    6BC1BEE2 2E409F96 E93D7E11 7393172A
                ", @"
                    9E99A7BF 31E71090 0662F65E 617C5184
                "),

            new("CMAC-AES192 #3", @"
                    8E73B0F7 DA0E6452 C810F32B 809079E5
                    62F8EAD2 522C6B7B
                ", @"
                    6BC1BEE2 2E409F96 E93D7E11 7393172A
                    AE2D8A57
                ", @"
                    3D75C194 ED960704 44A9FA7E C740ECF8
                "),

            new("CMAC-AES192 #4", @"
                    8E73B0F7 DA0E6452 C810F32B 809079E5
                    62F8EAD2 522C6B7B
                ", @"
                    6BC1BEE2 2E409F96 E93D7E11 7393172A
                    AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51
                    30C81C46 A35CE411 E5FBC119 1A0A52EF
                    F69F2445 DF4F9B17 AD2B417B E66C3710
                ", @"
                    A1D5DF0E ED790F79 4D775896 59F39A11
                "),

            new("CMAC-AES256 #1", @"
                    603DEB10 15CA71BE 2B73AEF0 857D7781
                    1F352C07 3B6108D7 2D9810A3 0914DFF4
                ", @"

                ", @"
                    028962F6 1B7BF89E FC6B551F 4667D983
                "),

            new("CMAC-AES256 #2", @"
                    603DEB10 15CA71BE 2B73AEF0 857D7781
                    1F352C07 3B6108D7 2D9810A3 0914DFF4
                ", @"
                    6BC1BEE2 2E409F96 E93D7E11 7393172A
                ", @"
                    28A7023F 452E8F82 BD4BF28D 8C37C35C
                "),

            new("CMAC-AES256 #3", @"
                    603DEB10 15CA71BE 2B73AEF0 857D7781
                    1F352C07 3B6108D7 2D9810A3 0914DFF4
                ", @"
                    6BC1BEE2 2E409F96 E93D7E11 7393172A
                    AE2D8A57
                ", @"
                    156727DC 0878944A 023C1FE0 3BAD6D93
                "),

            new("CMAC-AES256 #4", @"
                    603DEB10 15CA71BE 2B73AEF0 857D7781
                    1F352C07 3B6108D7 2D9810A3 0914DFF4
                ", @"
                    6BC1BEE2 2E409F96 E93D7E11 7393172A
                    AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51
                    30C81C46 A35CE411 E5FBC119 1A0A52EF
                    F69F2445 DF4F9B17 AD2B417B E66C3710
                ", @"
                    E1992190 549F6ED5 696A2C05 6C315410
                "),

        };
        All = testVectors.AsReadOnly();
    }
}
