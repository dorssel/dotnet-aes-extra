// SPDX-FileCopyrightText: 2025 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Reflection;

namespace UnitTests;

[AttributeUsage(AttributeTargets.Method)]
sealed class MbedTlsPbkdf2AesCmacPrf128TestVectorSourceAttribute
    : Attribute
    , ITestDataSource
{
    public MbedTlsPbkdf2AesCmacPrf128TestVectorSourceAttribute()
    {
    }

    public IEnumerable<object[]> GetData(MethodInfo methodInfo)
    {
        return MbedTlsPbkdf2AesCmacPrf128TestVector.All.Select(tv => new object[] { tv });
    }

    public string GetDisplayName(MethodInfo methodInfo, object?[]? data)
    {
        var testVector = data?.FirstOrDefault() as MbedTlsPbkdf2AesCmacPrf128TestVector;
        return $"{methodInfo.Name}({testVector?.Name})";
    }
}
