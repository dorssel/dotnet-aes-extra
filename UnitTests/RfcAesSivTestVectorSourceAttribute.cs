﻿// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Reflection;

namespace UnitTests;

[AttributeUsage(AttributeTargets.Method)]
sealed class RfcAesSivTestVectorSourceAttribute
    : Attribute
    , ITestDataSource
{
    public RfcAesSivTestVectorSourceAttribute()
    {
    }

    public IEnumerable<object[]> GetData(MethodInfo methodInfo)
    {
        return RfcAesSivTestVector.All.Select(tv => new object[] { tv });
    }

    public string GetDisplayName(MethodInfo methodInfo, object?[]? data)
    {
        var testVector = data?.FirstOrDefault() as RfcAesSivTestVector;
        return $"{methodInfo.Name}({testVector?.Name})";
    }
}
