// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Reflection;

namespace UnitTests;

[AttributeUsage(AttributeTargets.Method)]
sealed class RfcAesSivTestVectorSourceAttribute(bool SingleAssociatedDataItem = false)
        : Attribute
    , ITestDataSource
{
    public bool SingleAssociatedDataItem { get; } = SingleAssociatedDataItem;

    public IEnumerable<object[]> GetData(MethodInfo methodInfo)
    {
        return RfcAesSivTestVector.All.Where(tv => !SingleAssociatedDataItem || tv.AD.Count + (tv.Nonce is null ? 0 : 1) == 1)
            .Select(tv => new object[] { tv });
    }

    public string GetDisplayName(MethodInfo methodInfo, object?[]? data)
    {
        var testVector = data?.FirstOrDefault() as RfcAesSivTestVector;
        return $"{methodInfo.Name}({testVector?.Name})";
    }
}
