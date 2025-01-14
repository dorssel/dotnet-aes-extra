// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace UnitTests;

[TestClass]
sealed class AesCmac_Tests
{
    const int BLOCKSIZE = 16;  // bytes
    const int BitsPerByte = 8;

    static readonly NistAesCmacSampleTestVector TestVector = NistAesCmacSampleTestVector.All.First(
        v => v.Key.Length == 192 / BitsPerByte && v.PT.Length > BLOCKSIZE);

    static byte[] TestKey => TestVector.Key.ToArray();
    static byte[] TestMessage => TestVector.PT.ToArray();
    static byte[] TestTag => TestVector.Tag.ToArray();

    static byte[] TestKeyNull => null!;
    static byte[] TestKeyInvalid { get; } = new byte[11];

    static byte[] TestMessageNull => null!;

    static Stream TestStream => new MemoryStream(TestMessage);
    static Stream TestStreamNull => null!;
    static Stream TestStreamInvalid { get; } = new NonReadableStream();

    static byte[] TestDestination { get; } = new byte[BLOCKSIZE];
    static byte[] TestDestinationShort { get; } = new byte[BLOCKSIZE - 1];
    static byte[] TestDestinationLong { get; } = new byte[BLOCKSIZE + 1];

    sealed class NonReadableStream : Stream
    {
        public override bool CanRead => false;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotImplementedException();

        public override long Position { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

        public override void Flush()
        {
            throw new NotImplementedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            throw new NotImplementedException();
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotImplementedException();
        }

        public override void SetLength(long value)
        {
            throw new NotImplementedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotImplementedException();
        }
    }

    [TestMethod]
    public void RegisterWithCryptoConfig()
    {
        AesCmac.RegisterWithCryptoConfig();
        using var aesCmac = (AesCmac?)CryptoConfig.CreateFromName("AesCmac");
        Assert.IsNotNull(aesCmac);
    }

    [TestMethod]
    public void RegisterWithCryptoConfig_Twice()
    {
        AesCmac.RegisterWithCryptoConfig();
        AesCmac.RegisterWithCryptoConfig();
        using var aesCmac = (AesCmac?)CryptoConfig.CreateFromName("Dorssel.Security.Cryptography.AesCmac");
        Assert.IsNotNull(aesCmac);
    }

    [TestMethod]
    public void Create()
    {
#pragma warning disable CS0618 // Type or member is obsolete
        using var aesCmac = AesCmac.Create();
#pragma warning restore CS0618 // Type or member is obsolete
        Assert.IsNotNull(aesCmac);
    }

    [TestMethod]
    public void Create_Name()
    {
#pragma warning disable CS0618 // Type or member is obsolete
        using var aesCmac = AesCmac.Create("AesCmac");
#pragma warning restore CS0618 // Type or member is obsolete
        Assert.IsNotNull(aesCmac);
    }

    [TestMethod]
    public void Create_FullName()
    {
#pragma warning disable CS0618 // Type or member is obsolete
        using var aesCmac = AesCmac.Create("Dorssel.Security.Cryptography.AesCmac");
#pragma warning restore CS0618 // Type or member is obsolete
        Assert.IsNotNull(aesCmac);
    }

    [TestMethod]
    public void Create_NullNameFails()
    {
        Assert.ThrowsException<ArgumentNullException>(() =>
        {
#pragma warning disable CS0618 // Type or member is obsolete
            using var aesCmac = AesCmac.Create(null!);
#pragma warning restore CS0618 // Type or member is obsolete
        });
    }

    [TestMethod]
    public void Create_OtherNameReturnsNull()
    {
#pragma warning disable CS0618 // Type or member is obsolete
        using var aesCmac = AesCmac.Create("SomeOtherName");
#pragma warning restore CS0618 // Type or member is obsolete
        Assert.IsNull(aesCmac);
    }

    [TestMethod]
    public void Constructor_Default()
    {
        using var aesCmac = new AesCmac();

        Assert.AreEqual(256, aesCmac.Key.Length * 8);
        CollectionAssert.AreNotEqual(new byte[aesCmac.Key.Length], aesCmac.Key);
    }

    [TestMethod]
    [DataRow(128)]
    [DataRow(192)]
    [DataRow(256)]
    public void Constructor_Int(int keySize)
    {
        using var aesCmac = new AesCmac(keySize);

        Assert.AreEqual(keySize, aesCmac.Key.Length * 8);
        CollectionAssert.AreNotEqual(new byte[aesCmac.Key.Length], aesCmac.Key);
    }

    [TestMethod]
    [DataRow(0)]
    [DataRow(1)]
    [DataRow(16)]
    [DataRow(24)]
    [DataRow(32)]
    public void Constructor_Int_Invalid(int keySize)
    {
        Assert.ThrowsException<CryptographicException>(() =>
        {
            using var aesCmac = new AesCmac(keySize);
        });
    }

    [TestMethod]
    [DataRow(128)]
    [DataRow(192)]
    [DataRow(256)]
    public void Constructor_Array(int keySize)
    {
        using var aesCmac = new AesCmac(new byte[keySize / 8]);
    }

    [TestMethod]
    [DataRow(0)]
    [DataRow(16)]
    [DataRow(24)]
    [DataRow(32)]
    public void Constructor_Array_Invalid(int keySize)
    {
        Assert.ThrowsException<CryptographicException>(() =>
        {
            using var aesCmac = new AesCmac(new byte[keySize / 8]);
        });
    }

    [TestMethod]
    public void Constructor_Array_Null()
    {
        Assert.ThrowsException<ArgumentNullException>(() =>
        {
            using var aesCmac = new AesCmac(TestKeyNull);
        });
    }

    [TestMethod]
    [DataRow(128)]
    [DataRow(192)]
    [DataRow(256)]
    public void Constructor_ReadOnlySpan(int keySize)
    {
        using var aesCmac = new AesCmac(new byte[keySize / 8].AsSpan());
    }

    [TestMethod]
    [DataRow(0)]
    [DataRow(16)]
    [DataRow(24)]
    [DataRow(32)]
    public void Constructor_ReadOnlySpan_Invalid(int keySize)
    {
        Assert.ThrowsException<CryptographicException>(() =>
        {
            using var aesCmac = new AesCmac(new byte[keySize / 8].AsSpan());
        });
    }

    [TestMethod]
    public void Dispose()
    {
        var aesCmac = new AesCmac();
        aesCmac.Dispose();
    }

    [TestMethod]
    public void Dispose_Double()
    {
        var aesCmac = new AesCmac();
        aesCmac.Dispose();
        aesCmac.Dispose();
    }

    [TestMethod]
    public void Key_Change()
    {
        var keys = NistAesCmacSampleTestVector.All
            .Select(tv => tv.Key.ToArray())
            .DistinctBy(BitConverter.ToString);

        using var aesCmac = new AesCmac();
        foreach (var key in keys)
        {
            aesCmac.Key = key;
            CollectionAssert.AreEqual(key, aesCmac.Key);
        }
    }

    [TestMethod]
    public void Key_ChangeWhileBusy()
    {
        using var aesCmac = new AesCmac();
        aesCmac.TransformBlock(new byte[1], 0, 0, null, 0);

        Assert.ThrowsException<InvalidOperationException>(() =>
        {
            aesCmac.Key = new byte[aesCmac.Key.Length];
        });
    }

    [TestMethod]
    public void Key_ChangeAfterDispose()
    {
        using var aesCmac = new AesCmac();
        aesCmac.Dispose();

        Assert.ThrowsException<ObjectDisposedException>(() =>
        {
            aesCmac.Key = TestKey;
        });
    }

    [TestMethod]
    public void ComputeHash_Segmented()
    {
        var testVector = NistAesCmacSampleTestVector.All.First(tv => tv.PT.Length == 64);

        using var aesCmac = new AesCmac(testVector.Key.ToArray());

        var pos = 0;
        void Transfer(int count)
        {
            aesCmac.TransformBlock(testVector.PT.ToArray(), pos, count, null, 0);
            pos += count;
        }

        // less than 1 block
        Transfer(16 - 3);
        // append to, but don't complete the partial block
        Transfer(2);
        // complete the partial block precisely
        Transfer(1);
        // more than 1 block, but not an exact multiple
        Transfer((2 * 16) - 3);
        // topping off the partial block + again less than 1 block
        Transfer(16);
        // remainder
        Transfer(testVector.PT.Length - pos);

        aesCmac.TransformFinalBlock([], 0, 0);

        CollectionAssert.AreEqual(testVector.Tag.ToArray(), aesCmac.Hash);
    }

    [TestMethod]
    public void ComputeHash_Reuse()
    {
        using var aesCmac = new AesCmac();
        foreach (var testVector in NistAesCmacSampleTestVector.All)
        {
            aesCmac.Key = testVector.Key.ToArray();
            var tag = aesCmac.ComputeHash(testVector.PT.ToArray());
            CollectionAssert.AreEqual(testVector.Tag.ToArray(), tag);
        }
    }

    [TestMethod]
    public void TryHashData()
    {
        var success = AesCmac.TryHashData(TestKey, TestMessage, TestDestination, out var bytesWritten);

        Assert.IsTrue(success);
        Assert.AreEqual(BLOCKSIZE, bytesWritten);
        CollectionAssert.AreEqual(TestTag, TestDestination);
    }

    [TestMethod]
    public void TryHashData_DestinationLong()
    {
        var success = AesCmac.TryHashData(TestKey, TestMessage, TestDestinationLong, out var bytesWritten);

        Assert.IsTrue(success);
        Assert.AreEqual(BLOCKSIZE, bytesWritten);
        CollectionAssert.AreEqual(TestTag, TestDestinationLong[..BLOCKSIZE]);
    }

    [TestMethod]
    public void TryHashData_DestinationShort()
    {
        var success = AesCmac.TryHashData(TestKey, TestMessage, TestDestinationShort, out var bytesWritten);

        Assert.IsFalse(success);
        Assert.AreEqual(0, bytesWritten);
    }

    [TestMethod]
    public void TryHashData_KeyInvalid()
    {
        Assert.ThrowsException<CryptographicException>(() =>
        {
            AesCmac.TryHashData(TestKeyInvalid, TestMessage, TestDestination, out var bytesWritten);
        });
    }

    [TestMethod]
    public void HashData_Array_Array()
    {
        var destination = AesCmac.HashData(TestKey, TestMessage);

        CollectionAssert.AreEqual(TestTag, destination);
    }

    [TestMethod]
    public void HashData_Array_Array_KeyNull()
    {
        Assert.ThrowsException<ArgumentNullException>(() =>
        {
            AesCmac.HashData(TestKeyNull, TestMessage);
        });
    }

    [TestMethod]
    public void HashData_Array_Array_KeyInvalid()
    {
        Assert.ThrowsException<CryptographicException>(() =>
        {
            AesCmac.HashData(TestKeyInvalid, TestMessage);
        });
    }

    [TestMethod]
    public void HashData_Array_Array_MessageNull()
    {
        Assert.ThrowsException<ArgumentNullException>(() =>
        {
            AesCmac.HashData(TestKey, TestMessageNull);
        });
    }

    [TestMethod]
    public void HashData_ReadOnlySpan_ReadOnlySpan()
    {
        var destination = AesCmac.HashData(TestKey.AsSpan(), TestMessage.AsSpan());

        CollectionAssert.AreEqual(TestTag, destination);
    }

    [TestMethod]
    public void HashData_ReadOnlySpan_ReadOnlySpan_KeyInvalid()
    {
        Assert.ThrowsException<CryptographicException>(() =>
        {
            AesCmac.HashData(TestKeyInvalid.AsSpan(), TestMessage.AsSpan());
        });
    }

    [TestMethod]
    public void HashData_ReadOnlySpan_ReadOnlySpan_Span()
    {
        var bytesWritten = AesCmac.HashData(TestKey.AsSpan(), TestMessage.AsSpan(), TestDestination.AsSpan());

        Assert.AreEqual(BLOCKSIZE, bytesWritten);
        CollectionAssert.AreEqual(TestTag, TestDestination);
    }

    [TestMethod]
    public void HashData_ReadOnlySpan_ReadOnlySpan_Span_KeyInvalid()
    {
        Assert.ThrowsException<CryptographicException>(() =>
        {
            AesCmac.HashData(TestKeyInvalid.AsSpan(), TestMessage.AsSpan(), TestDestination.AsSpan());
        });
    }

    [TestMethod]
    public void HashData_ReadOnlySpan_ReadOnlySpan_Span_DestinationShort()
    {
        Assert.ThrowsException<ArgumentException>(() =>
        {
            AesCmac.HashData(TestKey.AsSpan(), TestMessage.AsSpan(), TestDestinationShort.AsSpan());
        });
    }

    [TestMethod]
    public void HashData_Array_Stream()
    {
        var destination = AesCmac.HashData(TestKey, TestStream);

        CollectionAssert.AreEqual(TestTag, destination);
    }

    [TestMethod]
    public void HashData_Array_Stream_KeyNull()
    {
        Assert.ThrowsException<ArgumentNullException>(() =>
        {
            AesCmac.HashData(TestKeyNull, TestStream);
        });
    }

    [TestMethod]
    public void HashData_Array_Stream_KeyInvalid()
    {
        Assert.ThrowsException<CryptographicException>(() =>
        {
            AesCmac.HashData(TestKeyInvalid, TestStream);
        });
    }

    [TestMethod]
    public void HashData_Array_Stream_StreamNull()
    {
        Assert.ThrowsException<ArgumentNullException>(() =>
        {
            AesCmac.HashData(TestKey, TestStreamNull);
        });
    }

    [TestMethod]
    public void HashData_Array_Stream_StreamInvalid()
    {
        Assert.ThrowsException<ArgumentException>(() =>
        {
            AesCmac.HashData(TestKey, TestStreamInvalid);
        });
    }

    [TestMethod]
    public void HashData_ReadOnlySpan_Stream()
    {
        var destination = AesCmac.HashData(TestKey.AsSpan(), TestStream);

        CollectionAssert.AreEqual(TestTag, destination);
    }

    [TestMethod]
    public void HashData_ReadOnlySpan_Stream_KeyInvalid()
    {
        Assert.ThrowsException<CryptographicException>(() =>
        {
            AesCmac.HashData(TestKeyInvalid.AsSpan(), TestStream);
        });
    }

    [TestMethod]
    public void HashData_ReadOnlySpan_Stream_StreamNull()
    {
        Assert.ThrowsException<ArgumentNullException>(() =>
        {
            AesCmac.HashData(TestKey.AsSpan(), TestStreamNull);
        });
    }

    [TestMethod]
    public void HashData_ReadOnlySpan_Stream_StreamInvalid()
    {
        Assert.ThrowsException<ArgumentException>(() =>
        {
            AesCmac.HashData(TestKey.AsSpan(), TestStreamInvalid);
        });
    }

    [TestMethod]
    public void HashData_ReadOnlySpan_Stream_Span()
    {
        var bytesWritten = AesCmac.HashData(TestKey.AsSpan(), TestStream, TestDestination.AsSpan());

        Assert.AreEqual(BLOCKSIZE, bytesWritten);
        CollectionAssert.AreEqual(TestTag, TestDestination);
    }

    [TestMethod]
    public void HashData_ReadOnlySpan_Stream_Span_KeyInvalid()
    {
        Assert.ThrowsException<CryptographicException>(() =>
        {
            AesCmac.HashData(TestKeyInvalid.AsSpan(), TestStream, TestDestination.AsSpan());
        });
    }

    [TestMethod]
    public void HashData_ReadOnlySpan_Stream_Span_StreamNull()
    {
        Assert.ThrowsException<ArgumentNullException>(() =>
        {
            AesCmac.HashData(TestKey.AsSpan(), TestStreamNull, TestDestination.AsSpan());
        });
    }

    [TestMethod]
    public void HashData_ReadOnlySpan_Stream_Span_DestinationShort()
    {
        Assert.ThrowsException<ArgumentException>(() =>
        {
            AesCmac.HashData(TestKey.AsSpan(), TestStream, TestDestinationShort.AsSpan());
        });
    }

    [TestMethod]
    public async Task HashDataAsync_Array_Stream()
    {
        var destination = await AesCmac.HashDataAsync(TestKey, TestStream);

        CollectionAssert.AreEqual(TestTag, destination);
    }

    [TestMethod]
    public async Task HashDataAsync_Array_Stream_KeyNull()
    {
        await Assert.ThrowsExceptionAsync<ArgumentNullException>(async () =>
        {
            await AesCmac.HashDataAsync(TestKeyNull, TestStream);
        });
    }

    [TestMethod]
    public async Task HashDataAsync_Array_Stream_KeyInvalid()
    {
        await Assert.ThrowsExceptionAsync<CryptographicException>(async () =>
        {
            await AesCmac.HashDataAsync(TestKeyInvalid, TestStream);
        });
    }

    [TestMethod]
    public async Task HashDataAsync_Array_Stream_StreamNull()
    {
        await Assert.ThrowsExceptionAsync<ArgumentNullException>(async () =>
        {
            await AesCmac.HashDataAsync(TestKey, TestStreamNull);
        });
    }

    [TestMethod]
    public async Task HashDataAsync_Array_Stream_StreamInvalid()
    {
        await Assert.ThrowsExceptionAsync<ArgumentException>(async () =>
        {
            await AesCmac.HashDataAsync(TestKey, TestStreamInvalid);
        });
    }

    [TestMethod]
    public async Task HashDataAsync_ReadOnlyMemory_Stream()
    {
        var destination = await AesCmac.HashDataAsync(TestKey.AsMemory(), TestStream);

        CollectionAssert.AreEqual(TestTag, destination);
    }

    [TestMethod]
    public async Task HashDataAsync_ReadOnlyMemory_Stream_KeyInvalid()
    {
        await Assert.ThrowsExceptionAsync<CryptographicException>(async () =>
        {
            await AesCmac.HashDataAsync(TestKeyInvalid.AsMemory(), TestStream);
        });
    }

    [TestMethod]
    public async Task HashDataAsync_ReadOnlyMemory_Stream_StreamNull()
    {
        await Assert.ThrowsExceptionAsync<ArgumentNullException>(async () =>
        {
            await AesCmac.HashDataAsync(TestKey.AsMemory(), TestStreamNull);
        });
    }

    [TestMethod]
    public async Task HashDataAsync_ReadOnlyMemory_Stream_StreamInvalid()
    {
        await Assert.ThrowsExceptionAsync<ArgumentException>(async () =>
        {
            await AesCmac.HashDataAsync(TestKey.AsMemory(), TestStreamInvalid);
        });
    }

    [TestMethod]
    public async Task HashDataAsync_ReadOnlyMemory_Stream_Memory()
    {
        var bytesWritten = await AesCmac.HashDataAsync(TestKey.AsMemory(), TestStream, TestDestination.AsMemory());

        Assert.AreEqual(BLOCKSIZE, bytesWritten);
        CollectionAssert.AreEqual(TestTag, TestDestination);
    }

    [TestMethod]
    public async Task HashDataAsync_ReadOnlyMemory_Stream_Memory_KeyInvalid()
    {
        await Assert.ThrowsExceptionAsync<CryptographicException>(async () =>
        {
            await AesCmac.HashDataAsync(TestKeyInvalid.AsMemory(), TestStream, TestDestination.AsMemory());
        });
    }

    [TestMethod]
    public async Task HashDataAsync_ReadOnlyMemory_Stream_Memory_StreamNull()
    {
        await Assert.ThrowsExceptionAsync<ArgumentNullException>(async () =>
        {
            await AesCmac.HashDataAsync(TestKey.AsMemory(), TestStreamNull, TestDestination.AsMemory());
        });
    }

    [TestMethod]
    public async Task HashDataAsync_ReadOnlyMemory_Stream_Memory_StreamInvalid()
    {
        await Assert.ThrowsExceptionAsync<ArgumentException>(async () =>
        {
            await AesCmac.HashDataAsync(TestKey.AsMemory(), TestStreamInvalid, TestDestination.AsMemory());
        });
    }

    [TestMethod]
    public async Task HashDataAsync_ReadOnlyMemory_Stream_Memory_DestinationShort()
    {
        await Assert.ThrowsExceptionAsync<ArgumentException>(async () =>
        {
            await AesCmac.HashDataAsync(TestKey.AsMemory(), TestStream, TestDestinationShort.AsMemory());
        });
    }
}
