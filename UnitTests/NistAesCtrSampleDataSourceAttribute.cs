using System.Reflection;

namespace UnitTests;

[AttributeUsage(AttributeTargets.Method)]
internal sealed class NistAesCtrSampleDataSourceAttribute
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

    public string GetDisplayName(MethodInfo methodInfo, object[] data)
    {
        var testVector = (NistAesCtrSampleTestVector)data[0];
        return $"{methodInfo.Name}({testVector.Name})";
    }
}
