// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Reflection;

namespace UnitTests;

[AttributeUsage(AttributeTargets.Method)]
sealed class NistAesCtrSampleDataSourceAttribute
    : Attribute
    , ITestDataSource
{
    public NistAesCtrSampleDataSourceAttribute()
    {
    }

    public IEnumerable<object[]> GetData(MethodInfo methodInfo)
    {
        return NistAesCtrSampleTestVector.All.Select(tv => new object[] { tv });
    }

    public string GetDisplayName(MethodInfo methodInfo, object?[]? data)
    {
        var testVector = data?.FirstOrDefault() as NistAesCtrSampleTestVector;
        return $"{methodInfo.Name}({testVector?.Name})";
    }
}
