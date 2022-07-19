// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace UnitTests
{
    class AccountingStream : Stream
    {
        public AccountingStream(Stream baseStream)
        {
            BaseStream = baseStream;
        }

        public override bool CanRead => BaseStream.CanRead;

        public override bool CanSeek => BaseStream.CanSeek;

        public override bool CanWrite => BaseStream.CanWrite;

        public override long Length => BaseStream.Length;

        public override long Position { get => BaseStream.Position; set => BaseStream.Position = value; }

        public override void Flush() => BaseStream.Flush();

        readonly Stream BaseStream;

        public long ReadByteCount { get; private set; }
        public long WriteByteCount { get; private set; }

        public override int Read(byte[] buffer, int offset, int count)
        {
            var result = BaseStream.Read(buffer, offset, count);
            ReadByteCount += result;
            return result;
        }

        public override long Seek(long offset, SeekOrigin origin) => BaseStream.Seek(offset, origin);

        public override void SetLength(long value) => BaseStream.SetLength(value);

        public override void Write(byte[] buffer, int offset, int count)
        {
            BaseStream.Write(buffer, offset, count);
            ReadByteCount += count;
        }
    }
}
