using System.Reflection;

namespace UnitTests;

[AttributeUsage(AttributeTargets.Method)]
internal sealed class NistAesCmacSampleDataSourceAttribute
    : Attribute
    , ITestDataSource
{
    public NistAesCmacSampleDataSourceAttribute()
    {
    }

    public IEnumerable<object[]> GetData(MethodInfo methodInfo)
    {
        return NistAesCmacSampleTestVector.All.Select(tv => new object[] { tv });
    }

    public string GetDisplayName(MethodInfo methodInfo, object[] data)
    {
        var testVector = (NistAesCmacSampleTestVector)data[0];
        return $"{methodInfo.Name}({testVector.Name})";
    }
}
