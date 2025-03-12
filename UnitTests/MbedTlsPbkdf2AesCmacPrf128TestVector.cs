// SPDX-FileCopyrightText: 2025 Frans van Dorsselaer
// SPDX-FileCopyrightText: The Mbed TLS Contributors
//
// SPDX-License-Identifier: MIT
// SPDX-License-Identifier: Apache-2.0

using System.Globalization;
using System.Runtime.Serialization;

namespace UnitTests;

[DataContract]
sealed record MbedTlsPbkdf2AesCmacPrf128TestVector
{
    public static IReadOnlyList<MbedTlsPbkdf2AesCmacPrf128TestVector> All { get; }

#pragma warning disable IDE1006 // Naming Styles
    [DataMember]
    string _Name { get; init; }
    [DataMember]
    byte[] _Password { get; init; }
    [DataMember]
    byte[] _Salt { get; init; }
    [DataMember]
    int _Iterations { get; init; }
    [DataMember]
    byte[] _Output { get; init; }
#pragma warning restore IDE1006 // Naming Styles

    public string Name => _Name;
    public ReadOnlyMemory<byte> Password => _Password;
    public ReadOnlyMemory<byte> Salt => _Salt;
    public int Iterations => _Iterations;
    public ReadOnlyMemory<byte> Output => _Output;

    MbedTlsPbkdf2AesCmacPrf128TestVector(string Name, string Password, string Salt, string Iterations, string Output)
    {
        _Name = Name;
        _Password = Convert.FromHexString(Password);
        _Salt = Convert.FromHexString(Salt);
        _Iterations = int.Parse(Iterations, NumberStyles.HexNumber);
        _Output = Convert.FromHexString(Output);
    }

    static MbedTlsPbkdf2AesCmacPrf128TestVector()
    {
        var testVectors = new List<MbedTlsPbkdf2AesCmacPrf128TestVector>();
        var name = string.Empty;
        foreach (var line in MbedTlsTestVectorData.Split('\n', '\r'))
        {
            if (line.StartsWith("PSA key derivation: PBKDF2-AES-CMAC-PRF-128, "))
            {
                name = line["PSA key derivation: PBKDF2-AES-CMAC-PRF-128, ".Length..];
                continue;
            }
            if (!line.StartsWith("derive_output:PSA_ALG_PBKDF2_AES_CMAC_PRF_128:"))
            {
                continue;
            }
            var parts = line.Split(':');
            var password = string.Empty;
            var salt = string.Empty;
            var cost = string.Empty;
            for (var i = 0; i < parts.Length; i++)
            {
                switch (parts[i])
                {
                    case "PSA_KEY_DERIVATION_INPUT_PASSWORD":
                        password += parts[i + 1].Trim('"');
                        break;
                    case "PSA_KEY_DERIVATION_INPUT_SALT":
                        salt += parts[i + 1].Trim('"');
                        break;
                    case "PSA_KEY_DERIVATION_INPUT_COST":
                        cost += parts[i + 1].Trim('"');
                        break;
                }
            }
            var output = parts[^6].Trim('"') + parts[^5].Trim('"');

            testVectors.Add(new(name, password, salt, cost, output));
        }
        All = testVectors.AsReadOnly();
    }

    // See: https://github.com/Mbed-TLS/TF-PSA-Crypto/blob/main/tests/suites/test_suite_psa_crypto.data
    // Licensed under Apache-2.0
    const string MbedTlsTestVectorData = """
        PSA key derivation: PBKDF2-AES-CMAC-PRF-128, Test Vector 1, 20+0
        depends_on:PSA_WANT_ALG_PBKDF2_AES_CMAC_PRF_128:PSA_WANT_ALG_CMAC:PSA_WANT_KEY_TYPE_AES
        derive_output:PSA_ALG_PBKDF2_AES_CMAC_PRF_128:PSA_KEY_DERIVATION_INPUT_COST:"01":PSA_SUCCESS:PSA_KEY_DERIVATION_INPUT_SALT:"73616c74":PSA_SUCCESS:PSA_KEY_DERIVATION_INPUT_PASSWORD:"70617373776f7264":PSA_SUCCESS:0:"":PSA_SUCCESS:"":20:"1b72f6419173a06e27777606a315876ec71227de":"":0:1:0  // DevSkim: ignore DS173237

        PSA key derivation: PBKDF2-AES-CMAC-PRF-128, Test Vector 1, 10+10
        depends_on:PSA_WANT_ALG_PBKDF2_AES_CMAC_PRF_128:PSA_WANT_ALG_CMAC:PSA_WANT_KEY_TYPE_AES
        derive_output:PSA_ALG_PBKDF2_AES_CMAC_PRF_128:PSA_KEY_DERIVATION_INPUT_COST:"01":PSA_SUCCESS:PSA_KEY_DERIVATION_INPUT_SALT:"73616c74":PSA_SUCCESS:PSA_KEY_DERIVATION_INPUT_PASSWORD:"70617373776f7264":PSA_SUCCESS:0:"":PSA_SUCCESS:"":20:"1b72f6419173a06e2777":"7606a315876ec71227de":0:1:0  // DevSkim: ignore DS173237

        PSA key derivation: PBKDF2-AES-CMAC-PRF-128, Test Vector 1, 0+20
        depends_on:PSA_WANT_ALG_PBKDF2_AES_CMAC_PRF_128:PSA_WANT_ALG_CMAC:PSA_WANT_KEY_TYPE_AES
        derive_output:PSA_ALG_PBKDF2_AES_CMAC_PRF_128:PSA_KEY_DERIVATION_INPUT_COST:"01":PSA_SUCCESS:PSA_KEY_DERIVATION_INPUT_SALT:"73616c74":PSA_SUCCESS:PSA_KEY_DERIVATION_INPUT_PASSWORD:"70617373776f7264":PSA_SUCCESS:0:"":PSA_SUCCESS:"":20:"":"1b72f6419173a06e27777606a315876ec71227de":0:1:0  // DevSkim: ignore DS173237

        PSA key derivation: PBKDF2-AES-CMAC-PRF-128, Test Vector 2
        depends_on:PSA_WANT_ALG_PBKDF2_AES_CMAC_PRF_128:PSA_WANT_ALG_CMAC:PSA_WANT_KEY_TYPE_AES
        derive_output:PSA_ALG_PBKDF2_AES_CMAC_PRF_128:PSA_KEY_DERIVATION_INPUT_COST:"02":PSA_SUCCESS:PSA_KEY_DERIVATION_INPUT_SALT:"73616c74":PSA_SUCCESS:PSA_KEY_DERIVATION_INPUT_PASSWORD:"70617373776f7264":PSA_SUCCESS:0:"":PSA_SUCCESS:"":20:"160597e28021fb3dd9cf088b007b688360fed438":"":0:1:0  // DevSkim: ignore DS173237

        PSA key derivation: PBKDF2-AES-CMAC-PRF-128, Test Vector 3
        depends_on:PSA_WANT_ALG_PBKDF2_AES_CMAC_PRF_128:PSA_WANT_ALG_CMAC:PSA_WANT_KEY_TYPE_AES
        derive_output:PSA_ALG_PBKDF2_AES_CMAC_PRF_128:PSA_KEY_DERIVATION_INPUT_COST:"1000":PSA_SUCCESS:PSA_KEY_DERIVATION_INPUT_SALT:"73616c74":PSA_SUCCESS:PSA_KEY_DERIVATION_INPUT_PASSWORD:"70617373776f7264":PSA_SUCCESS:0:"":PSA_SUCCESS:"":20:"38ba9795fe87e47d519eacb77e82e35daa795870":"":0:1:0  // DevSkim: ignore DS173237

        PSA key derivation: PBKDF2-AES-CMAC-PRF-128, Test Vector 4
        depends_on:PSA_WANT_ALG_PBKDF2_AES_CMAC_PRF_128:PSA_WANT_ALG_CMAC:PSA_WANT_KEY_TYPE_AES
        derive_output:PSA_ALG_PBKDF2_AES_CMAC_PRF_128:PSA_KEY_DERIVATION_INPUT_COST:"1000":PSA_SUCCESS:PSA_KEY_DERIVATION_INPUT_SALT:"73616c7453414c5473616c7453414c5473616c7453414c5473616c7453414c5473616c74":PSA_SUCCESS:PSA_KEY_DERIVATION_INPUT_PASSWORD:"70617373776f726450415353574f524470617373776f7264":PSA_SUCCESS:0:"":PSA_SUCCESS:"":25:"25e7c43283d2e98cb6d9537a783e93153a45595a876779e00d":"":0:1:0  // DevSkim: ignore DS173237

        PSA key derivation: PBKDF2-AES-CMAC-PRF-128, Test Vector 5
        depends_on:PSA_WANT_ALG_PBKDF2_AES_CMAC_PRF_128:PSA_WANT_ALG_CMAC:PSA_WANT_KEY_TYPE_AES
        derive_output:PSA_ALG_PBKDF2_AES_CMAC_PRF_128:PSA_KEY_DERIVATION_INPUT_COST:"1000":PSA_SUCCESS:PSA_KEY_DERIVATION_INPUT_SALT:"7361006c74":PSA_SUCCESS:PSA_KEY_DERIVATION_INPUT_PASSWORD:"7061737300776f7264":PSA_SUCCESS:0:"":PSA_SUCCESS:"":16:"3d2828c5a437d781e7733ca353c40579":"":0:1:0  // DevSkim: ignore DS173237

        PSA key derivation: PBKDF2-AES-CMAC-PRF-128, Test Vector 6
        depends_on:PSA_WANT_ALG_PBKDF2_AES_CMAC_PRF_128:PSA_WANT_ALG_CMAC:PSA_WANT_KEY_TYPE_AES
        derive_output:PSA_ALG_PBKDF2_AES_CMAC_PRF_128:PSA_KEY_DERIVATION_INPUT_COST:"01":PSA_SUCCESS:PSA_KEY_DERIVATION_INPUT_SALT:"73616c74":PSA_SUCCESS:PSA_KEY_DERIVATION_INPUT_PASSWORD:"706173737764":PSA_SUCCESS:0:"":PSA_SUCCESS:"":64:"28e288c6345bb5ecf7ca70274208a3ba0f1148b5868537d5e09d3ee6813b1f524d9ecbf864eb814a46cda50ad5ec4c0dc03578c6c5fb4a3f9880deb5cab537e4":"":0:1:0  // DevSkim: ignore DS173237

        PSA key derivation: PBKDF2-AES-CMAC-PRF-128, empty direct password
        depends_on:PSA_WANT_ALG_PBKDF2_AES_CMAC_PRF_128:PSA_WANT_ALG_CMAC:PSA_WANT_KEY_TYPE_AES
        derive_output:PSA_ALG_PBKDF2_AES_CMAC_PRF_128:PSA_KEY_DERIVATION_INPUT_COST:"1000":PSA_SUCCESS:PSA_KEY_DERIVATION_INPUT_SALT:"73616c74":PSA_SUCCESS:PSA_KEY_DERIVATION_INPUT_PASSWORD:"":PSA_SUCCESS:0:"":PSA_SUCCESS:"":16:"db00f3996d041b415eb273362d8c8c83":"":0:0:0  // DevSkim: ignore DS173237

        PSA key derivation: PBKDF2-AES-CMAC-PRF-128, 16 byte password
        depends_on:PSA_WANT_ALG_PBKDF2_AES_CMAC_PRF_128:PSA_WANT_ALG_CMAC:PSA_WANT_KEY_TYPE_AES
        derive_output:PSA_ALG_PBKDF2_AES_CMAC_PRF_128:PSA_KEY_DERIVATION_INPUT_COST:"1000":PSA_SUCCESS:PSA_KEY_DERIVATION_INPUT_SALT:"73616c74":PSA_SUCCESS:PSA_KEY_DERIVATION_INPUT_PASSWORD:"70617373776f726470617373776f7264":PSA_SUCCESS:0:"":PSA_SUCCESS:"":16:"c4c112c6e1e3b8757640603dec78825f":"":0:1:0  // DevSkim: ignore DS173237

        PSA key derivation: PBKDF2-AES-CMAC-PRF-128, Test vector 1, salt in two step
        depends_on:PSA_WANT_ALG_PBKDF2_AES_CMAC_PRF_128:PSA_WANT_ALG_CMAC:PSA_WANT_KEY_TYPE_AES
        derive_output:PSA_ALG_PBKDF2_AES_CMAC_PRF_128:PSA_KEY_DERIVATION_INPUT_COST:"01":PSA_SUCCESS:PSA_KEY_DERIVATION_INPUT_SALT:"7361":PSA_SUCCESS:PSA_KEY_DERIVATION_INPUT_SALT:"6c74":PSA_SUCCESS:PSA_KEY_DERIVATION_INPUT_PASSWORD:"70617373776f7264":PSA_SUCCESS:"":20:"1b72f6419173a06e27777606a315876ec71227de":"":0:1:0  // DevSkim: ignore DS173237

        PSA key derivation: PBKDF2-AES-CMAC-PRF-128, Test vector 1, password as key, derive key
        depends_on:PSA_WANT_ALG_PBKDF2_AES_CMAC_PRF_128:PSA_WANT_ALG_CMAC:PSA_WANT_KEY_TYPE_AES
        derive_output:PSA_ALG_PBKDF2_AES_CMAC_PRF_128:PSA_KEY_DERIVATION_INPUT_COST:"01":PSA_SUCCESS:PSA_KEY_DERIVATION_INPUT_SALT:"73616c74":PSA_SUCCESS:PSA_KEY_DERIVATION_INPUT_PASSWORD:"70617373776f7264":PSA_SUCCESS:0:"":PSA_SUCCESS:"":20:"1b72f6419173a06e27777606a315876ec71227de":"":0:1:1  // DevSkim: ignore DS173237

        PSA key derivation: PBKDF2-AES-CMAC-PRF-128, Test vector 1, password as bytes
        depends_on:PSA_WANT_ALG_PBKDF2_AES_CMAC_PRF_128:PSA_WANT_ALG_CMAC:PSA_WANT_KEY_TYPE_AES
        derive_output:PSA_ALG_PBKDF2_AES_CMAC_PRF_128:PSA_KEY_DERIVATION_INPUT_COST:"01":PSA_SUCCESS:PSA_KEY_DERIVATION_INPUT_SALT:"73616c74":PSA_SUCCESS:PSA_KEY_DERIVATION_INPUT_PASSWORD:"70617373776f7264":PSA_SUCCESS:0:"":PSA_SUCCESS:"":20:"1b72f6419173a06e27777606a315876ec71227de":"":0:0:0  // DevSkim: ignore DS173237

        PSA key derivation: PBKDF2-AES-CMAC-PRF-128, Test vector 1, password as bytes, derive key
        depends_on:PSA_WANT_ALG_PBKDF2_AES_CMAC_PRF_128:PSA_WANT_ALG_CMAC:PSA_WANT_KEY_TYPE_AES
        derive_output:PSA_ALG_PBKDF2_AES_CMAC_PRF_128:PSA_KEY_DERIVATION_INPUT_COST:"01":PSA_SUCCESS:PSA_KEY_DERIVATION_INPUT_SALT:"73616c74":PSA_SUCCESS:PSA_KEY_DERIVATION_INPUT_PASSWORD:"70617373776f7264":PSA_SUCCESS:0:"":PSA_SUCCESS:"":20:"1b72f6419173a06e27777606a315876ec71227de":"":0:0:1  // DevSkim: ignore DS173237

        """;
}
