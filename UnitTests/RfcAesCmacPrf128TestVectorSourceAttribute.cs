// SPDX-FileCopyrightText: 2025 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Reflection;

namespace UnitTests;

[AttributeUsage(AttributeTargets.Method)]
sealed class RfcAesCmacPrf128TestVectorSourceAttribute()
    : Attribute
    , ITestDataSource
{
    public IEnumerable<object[]> GetData(MethodInfo methodInfo)
    {
        return RfcAesCmacPrf128TestVector.All.Select(tv => new object[] { tv });
    }

    public string GetDisplayName(MethodInfo methodInfo, object?[]? data)
    {
        var testVector = data?.FirstOrDefault() as RfcAesCmacPrf128TestVector;
        return $"{methodInfo.Name}({testVector?.Name})";
    }
}
