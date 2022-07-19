﻿// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Text;
using System.Text.RegularExpressions;

namespace UnitTests;

public record NistAesCtrSampleTestVector
{
    public static IReadOnlyList<NistAesCtrSampleTestVector> All { get; }

    public string Section { get; }
    public string Name { get; }
    public ReadOnlyMemory<byte> Key { get; }
    public ReadOnlyMemory<byte> InitialCounter { get; }
    public ReadOnlyMemory<byte> Plaintext { get; }
    public ReadOnlyMemory<byte> Ciphertext { get; }

    NistAesCtrSampleTestVector(string Section, string Name, string Data)
    {
        this.Section = Section;
        this.Name = Name;

        var keyHex = new StringBuilder();
        var initialCounterHex = new StringBuilder();
        var plaintextHex = new StringBuilder();
        var ciphertextHex = new StringBuilder();
        foreach (var rawLine in Data.Split(new char[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)) {
            var line = rawLine.Trim();
            var match = Regex.Match(line, "([0-9a-fA-F]+)$");
            if (match.Success)
            {
                var hex = match.Groups[1].Value;
                if (line.StartsWith("Key") /* || line.StartsWith(" ") */)
                {
                    keyHex.Append(hex);
                }
                else if (line.StartsWith("Init."))
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
        Key = Convert.FromHexString(keyHex.ToString());
        InitialCounter = Convert.FromHexString(initialCounterHex.ToString());
        Plaintext = Convert.FromHexString(plaintextHex.ToString());
        Ciphertext = Convert.FromHexString(ciphertextHex.ToString());
    }

    static NistAesCtrSampleTestVector()
    {
        var testVectors = new List<NistAesCtrSampleTestVector>
        {
            new("F.5.1", "CTR-AES128.Encrypt", @"
                    Key            2b7e151628aed2a6abf7158809cf4f3c
                    Init. Counter  f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
                    Block #1
                    Input Block    f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
                    Output Block   ec8cdf7398607cb0f2d21675ea9ea1e4
                    Plaintext      6bc1bee22e409f96e93d7e117393172a
                    Ciphertext     874d6191b620e3261bef6864990db6ce
                    Block #2
                    Input Block    f0f1f2f3f4f5f6f7f8f9fafbfcfdff00
                    Output Block   362b7c3c6773516318a077d7fc5073ae
                    Plaintext      ae2d8a571e03ac9c9eb76fac45af8e51
                    Ciphertext     9806f66b7970fdff8617187bb9fffdff
                    Block #3
                    Input Block    f0f1f2f3f4f5f6f7f8f9fafbfcfdff01
                    Output Block   6a2cc3787889374fbeb4c81b17ba6c44
                    Plaintext      30c81c46a35ce411e5fbc1191a0a52ef
                    Ciphertext     5ae4df3edbd5d35e5b4f09020db03eab
                    Block #4
                    Input Block    f0f1f2f3f4f5f6f7f8f9fafbfcfdff02
                    Output Block   e89c399ff0f198c6d40a31db156cabfe
                    Plaintext      f69f2445df4f9b17ad2b417be66c3710
                    Ciphertext     1e031dda2fbe03d1792170a0f3009cee
                "),
        };
        All = testVectors.AsReadOnly();
    }
}
