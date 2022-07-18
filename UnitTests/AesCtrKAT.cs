namespace UnitTests;

[TestClass]
public class AesCtrKAT
{
    [TestMethod]
    [TestCategory("NIST")]
    [NistAesCtrSampleDataSource(true)]
    public void NistEncrypt(NistAesCtrSampleTestVector testVector)
    {
        _ = testVector ?? throw new ArgumentNullException(nameof(testVector));

        using var aes = AesCtr.Create();
        aes.Key = testVector.Key.ToArray();
        aes.IV = testVector.InitialCounter.ToArray();
        using var memoryStream = new MemoryStream();
        {
#pragma warning disable CA5401
            using var stream = new CryptoStream(memoryStream, aes.CreateEncryptor(), CryptoStreamMode.Write);
#pragma warning restore CA5401
            stream.Write(testVector.Plaintext.Span);
        }
        Assert.IsTrue(Enumerable.SequenceEqual(testVector.Ciphertext.ToArray(), memoryStream.ToArray()));
    }
}
