using System;
using System.IO;
using System.Linq;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    /// <summary>Tests for the decryption of version 2 SEIPD packets (RFC 9580 5.13.2).</summary>
    [TestFixture]
    public class PgpAeadStreamTest
    {
        private static readonly SecureRandom Random = new SecureRandom();

        // The decrypted contents of the SEIPD packets in RFC 9580 A.9 to A.11: a literal data packet "Hello, world!"
        private const string LiteralDataPacket = "cb13620000000000 48656c6c6f2c20776f726c6421";

        public class Rfc9580Vector
        {
            internal string File, SessionKey, HkdfOutput, Padding;
            internal SymmetricKeyAlgorithmTag Cipher;
            internal AeadAlgorithmTag Aead;

            public override string ToString() => Aead.ToString();
        }

        private static readonly Rfc9580Vector[] Vectors =
        {
            new Rfc9580Vector
            {
                File = "a9-eax-message.asc", Cipher = SymmetricKeyAlgorithmTag.Aes128, Aead = AeadAlgorithmTag.Eax,
                SessionKey = "3881bafe98541245 9b86c36f98cb9a5e",
                HkdfOutput = "b50422ac1c26be9ddd831d5bbb36b64f78b833f2e94a60c0",
                Padding = "d50eae5bf0cd6705500355816cb0c8ff",
            },
            new Rfc9580Vector
            {
                File = "a10-ocb-message.asc", Cipher = SymmetricKeyAlgorithmTag.Aes128, Aead = AeadAlgorithmTag.Ocb,
                SessionKey = "28e79ab82397d3c63de24ac217d7b791",
                HkdfOutput = "71662a11ee5b4e08144e6de883a00999ebde12bb570dcf",
                Padding = "d50eae6aa1649b56aa835b2613902bd2",
            },
            new Rfc9580Vector
            {
                File = "a11-gcm-message.asc", Cipher = SymmetricKeyAlgorithmTag.Aes128, Aead = AeadAlgorithmTag.Gcm,
                SessionKey = "1936fc8568980274bb900d8319360c77",
                HkdfOutput = "ea1438803cb8a47740ce9b54c338778d4d2bdc2b",
                Padding = "d50e1ce2269a9eddef81032172b7ed7c",
            },
        };

        private static byte[] Hex2(string hex) => Hex.Decode(hex.Replace(" ", ""));

        private static PgpEncryptedData ParseSingle(byte[] message)
        {
            var list = (PgpEncryptedDataList)new PgpObjectFactory(message).NextPgpObject();
            return list[0];
        }

        [TestCaseSource(nameof(Vectors))]
        public void Rfc9580Appendix(Rfc9580Vector vector)
        {
            byte[] message = PgpV6TestUtilities.LoadRfc9580(vector.File);
            byte[][] packets = PgpUnsupportedVersionTest.SplitPackets(message);
            var seipd = PgpV6TestUtilities.ReadPacket<SymmetricEncIntegrityPacket>(packets[1]);
            byte[] sessionKey = Hex2(vector.SessionKey);

            // HKDF output: message key followed by the first 8 octets less than a nonce of the IV
            byte[] hkdf = PgpAead.Hkdf(sessionKey, seipd.GetSalt(), seipd.GetAAData(), 16 + AeadUtilities.GetIVLength(
                vector.Aead) - 8);
            Assert.That(Hex.ToHexString(hkdf), Is.EqualTo(vector.HkdfOutput));

            byte[][] keyAndIv = PgpAead.DeriveMessageKeyAndIv(vector.Cipher, vector.Aead, sessionKey, seipd.GetSalt(),
                seipd.GetAAData());
            Assert.That(Hex.ToHexString(keyAndIv[0]), Is.EqualTo(vector.HkdfOutput.Substring(0, 32)));

            // the nonce of chunk 0 is the IV followed by a zero chunk index
            byte[] nonce = new byte[keyAndIv[1].Length];
            PgpAead.CreateNonce(keyAndIv[1], 0, nonce);
            Assert.That(Hex.ToHexString(nonce), Is.EqualTo(vector.HkdfOutput.Substring(32) + new string('0', 16)));

            // the decrypted data is a literal data packet followed by a padding packet
            PgpEncryptedData encData = ParseSingle(message);
            Assert.That(encData.IsAead, Is.True);
            Assert.That(encData.IsIntegrityProtected(), Is.True);

            using (Stream stream = encData.InitAeadDecStream(sessionKey))
            {
                byte[] plaintext = Streams.ReadAll(stream);
                Assert.That(Hex.ToHexString(plaintext), Is.EqualTo(Hex.ToHexString(Hex2(LiteralDataPacket))
                    + vector.Padding));
                Assert.That(encData.Verify(), Is.True);
            }
        }

        /// <summary>Encrypt the plaintext as a v2 SEIPD packet, independently of the production code.</summary>
        internal static byte[] EncryptSeipd(SymmetricKeyAlgorithmTag cipher, AeadAlgorithmTag aead,
            int chunkSizeOctet, byte[] sessionKey, byte[] salt, byte[] plaintext)
        {
            byte[] aad = SymmetricEncIntegrityPacket.CreateAAData(cipher, aead, chunkSizeOctet);
            byte[][] keyAndIv = PgpAead.DeriveMessageKeyAndIv(cipher, aead, sessionKey, salt, aad);
            byte[] nonce = new byte[keyAndIv[1].Length];
            int chunkLength = 1 << (chunkSizeOctet + 6);

            var body = new MemoryStream();
            body.Write(new byte[]{ 2, (byte)cipher, (byte)aead, (byte)chunkSizeOctet }, 0, 4);
            body.Write(salt, 0, salt.Length);

            long chunkIndex = 0;
            for (int pos = 0; pos < plaintext.Length; pos += chunkLength)
            {
                int length = System.Math.Min(chunkLength, plaintext.Length - pos);
                PgpAead.CreateNonce(keyAndIv[1], chunkIndex++, nonce);
                byte[] chunk = PgpAead.EncryptOneShot(cipher, aead, keyAndIv[0], nonce, aad,
                    Arrays.CopyOfRange(plaintext, pos, pos + length));
                body.Write(chunk, 0, chunk.Length);
            }

            byte[] finalAad = Arrays.Concatenate(aad, Pack.UInt64_To_BE((ulong)plaintext.Length));
            PgpAead.CreateNonce(keyAndIv[1], chunkIndex, nonce);
            byte[] finalTag = PgpAead.EncryptOneShot(cipher, aead, keyAndIv[0], nonce, finalAad, new byte[0]);
            body.Write(finalTag, 0, finalTag.Length);

            return PgpV6TestUtilities.NewFormatPacket(PacketTag.SymmetricEncryptedIntegrityProtected, body.ToArray());
        }

        // A v6 SKESK that goes with a v2 SEIPD packet; its content is not used by these tests
        private static byte[] SkeskPacket() =>
            PgpUnsupportedVersionTest.SplitPackets(PgpV6TestUtilities.LoadRfc9580("a10-ocb-message.asc"))[0];

        private static Stream Decrypt(byte[] seipdPacket, byte[] sessionKey, out PgpEncryptedData encData)
        {
            encData = ParseSingle(Arrays.Concatenate(SkeskPacket(), seipdPacket));
            return encData.InitAeadDecStream(sessionKey);
        }

        private static byte[] Plaintext(int length)
        {
            byte[] result = new byte[length];
            Random.NextBytes(result);
            return result;
        }

        private static readonly AeadAlgorithmTag[] AeadModes = { AeadAlgorithmTag.Eax, AeadAlgorithmTag.Ocb,
            AeadAlgorithmTag.Gcm };

        [Test]
        public void ChunkBoundaries()
        {
            foreach (var aead in AeadModes)
            {
                foreach (int chunkSizeOctet in new[]{ 0, 12 })
                {
                    int chunk = 1 << (chunkSizeOctet + 6);
                    foreach (int length in new[]{ 0, 1, chunk - 1, chunk, chunk + 1, 3 * chunk })
                    {
                        byte[] sessionKey = Plaintext(16);
                        byte[] plaintext = Plaintext(length);
                        byte[] seipd = EncryptSeipd(SymmetricKeyAlgorithmTag.Aes128, aead, chunkSizeOctet, sessionKey,
                            Plaintext(32), plaintext);

                        using (Stream stream = Decrypt(seipd, sessionKey,
                            out PgpEncryptedData encData))
                        {
                            Assert.That(Streams.ReadAll(stream), Is.EqualTo(plaintext),
                                $"{aead}, chunk octet {chunkSizeOctet}, length {length}");
                            Assert.That(encData.Verify(), Is.True);
                        }
                    }
                }
            }
        }

        [Test]
        public void ReadSizes()
        {
            byte[] sessionKey = Plaintext(16);
            byte[] plaintext = Plaintext(5 * 64 + 17);
            byte[] seipd = EncryptSeipd(SymmetricKeyAlgorithmTag.Aes128, AeadAlgorithmTag.Ocb, 0, sessionKey,
                Plaintext(32), plaintext);

            foreach (int bufferSize in new[]{ 1, 7, 64, 65536 })
            {
                using (Stream stream = Decrypt(seipd, sessionKey, out _))
                {
                    var result = new MemoryStream();
                    byte[] buffer = new byte[bufferSize];
                    int read;
                    while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        result.Write(buffer, 0, read);
                    }
                    Assert.That(result.ToArray(), Is.EqualTo(plaintext), "buffer size " + bufferSize);
                }
            }

            // random sizes
            using (Stream stream = Decrypt(seipd, sessionKey, out _))
            {
                var result = new MemoryStream();
                int read;
                do
                {
                    byte[] buffer = new byte[1 + Random.Next(100)];
                    read = stream.Read(buffer, 0, buffer.Length);
                    result.Write(buffer, 0, read);
                }
                while (read > 0);
                Assert.That(result.ToArray(), Is.EqualTo(plaintext));
            }

            // single octets
            using (Stream stream = Decrypt(seipd, sessionKey, out _))
            {
                var result = new MemoryStream();
                int b;
                while ((b = stream.ReadByte()) >= 0)
                {
                    result.WriteByte((byte)b);
                }
                Assert.That(result.ToArray(), Is.EqualTo(plaintext));
            }
        }

        /// <summary>Read until the stream ends or fails; returns the octets read and the exception, if any.</summary>
        private static byte[] ReadUntilEnd(Stream stream, out Exception failure)
        {
            failure = null;
            var result = new MemoryStream();
            try
            {
                byte[] buffer = new byte[37];
                int read;
                while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    result.Write(buffer, 0, read);
                }
            }
            catch (Exception e)
            {
                failure = e;
            }
            return result.ToArray();
        }

        private static readonly SymmetricKeyAlgorithmTag Aes = SymmetricKeyAlgorithmTag.Aes128;

        [Test]
        public void ModifiedChunksAreRejectedBeforeRelease()
        {
            foreach (var aead in AeadModes)
            {
                byte[] sessionKey = Plaintext(16);
                int chunks = 5;
                byte[] plaintext = Plaintext(chunks * 64 - 20);
                byte[] seipd = EncryptSeipd(Aes, aead, 0, sessionKey, Plaintext(32), plaintext);
                // the first octet of the chunk data: all but the chunks' tags, the final tag and the plaintext
                int dataStart = seipd.Length - (plaintext.Length + chunks * 16 + 16);

                for (int k = 0; k < chunks; ++k)
                {
                    int chunkStart = dataStart + k * (64 + 16);
                    int chunkEnd = chunkStart + System.Math.Min(64, plaintext.Length - k * 64);

                    // a flipped octet in the ciphertext, and in the tag, of chunk k
                    foreach (int position in new[]{ chunkStart, chunkEnd, chunkEnd + 15 })
                    {
                        byte[] modified = Arrays.Clone(seipd);
                        modified[position] ^= 0x01;

                        using (Stream stream = Decrypt(modified, sessionKey, out PgpEncryptedData encData))
                        {
                            byte[] read = ReadUntilEnd(stream, out Exception failure);

                            Assert.That(failure, Is.InstanceOf<PgpDataValidationException>(),
                                $"{aead}, chunk {k}, octet {position}");
                            Assert.That(read.Length, Is.LessThanOrEqualTo(k * 64));
                            Assert.That(read, Is.EqualTo(Arrays.CopyOfRange(plaintext, 0, read.Length)));
                            Assert.That(encData.Verify(), Is.False);

                            // the stream stays failed
                            Assert.Throws<PgpDataValidationException>(() => stream.ReadByte());
                        }
                    }
                }

                // the final tag
                byte[] finalModified = Arrays.Clone(seipd);
                finalModified[finalModified.Length - 1] ^= 0x80;
                using (Stream stream = Decrypt(finalModified, sessionKey, out PgpEncryptedData data))
                {
                    byte[] read = ReadUntilEnd(stream, out Exception failure);
                    Assert.That(failure, Is.InstanceOf<PgpDataValidationException>());
                    Assert.That(read.Length, Is.LessThan(plaintext.Length));
                    Assert.That(data.Verify(), Is.False);
                }
            }
        }

        [Test]
        public void MissingFinalTagIsDetected()
        {
            byte[] sessionKey = Plaintext(16);
            byte[] plaintext = Plaintext(3 * 64);
            byte[] seipd = EncryptSeipd(Aes, AeadAlgorithmTag.Gcm, 0, sessionKey, Plaintext(32), plaintext);

            // drop the final tag: the packet ends at a chunk boundary
            byte[] truncated = Arrays.CopyOfRange(seipd, 0, seipd.Length - 16);
            truncated = FixLength(truncated, seipd);

            using (Stream stream = Decrypt(truncated, sessionKey, out PgpEncryptedData encData))
            {
                ReadUntilEnd(stream, out Exception failure);
                Assert.That(failure, Is.InstanceOf<PgpDataValidationException>());
                Assert.That(encData.Verify(), Is.False);
            }
        }

        /// <summary>Re-encode the packet header after octets were removed from or added to the body.</summary>
        private static byte[] FixLength(byte[] modified, byte[] original)
        {
            byte[] body = Arrays.CopyOfRange(modified, HeaderLength(original), modified.Length);
            return PgpV6TestUtilities.NewFormatPacket(PacketTag.SymmetricEncryptedIntegrityProtected, body);
        }

        private static int HeaderLength(byte[] packet)
        {
            if (packet[1] < 192)
                return 2;
            if (packet[1] < 224)
                return 3;
            return 6;
        }

        [Test]
        public void ReorderedAndDuplicatedChunksAreRejected()
        {
            byte[] sessionKey = Plaintext(16);
            byte[] plaintext = Plaintext(4 * 64);
            byte[] seipd = EncryptSeipd(Aes, AeadAlgorithmTag.Ocb, 0, sessionKey, Plaintext(32), plaintext);

            int header = HeaderLength(seipd);
            int dataStart = header + 4 + 32;
            int chunkSize = 64 + 16;
            byte[][] chunks = Enumerable.Range(0, 4)
                .Select(i => Arrays.CopyOfRange(seipd, dataStart + i * chunkSize, dataStart + (i + 1) * chunkSize))
                .ToArray();
            byte[] prefix = Arrays.CopyOfRange(seipd, header, dataStart);
            byte[] finalTag = Arrays.CopyOfRange(seipd, seipd.Length - 16, seipd.Length);

            byte[] Assemble(params byte[][] parts) => PgpV6TestUtilities.NewFormatPacket(
                PacketTag.SymmetricEncryptedIntegrityProtected, Arrays.ConcatenateAll(parts));

            var modifications = new[]
            {
                Assemble(prefix, chunks[1], chunks[0], chunks[2], chunks[3], finalTag),    // swapped
                Assemble(prefix, chunks[0], chunks[1], chunks[1], chunks[3], finalTag),    // duplicated
                Assemble(prefix, chunks[0], chunks[1], chunks[2], finalTag),                // chunk removed
                Assemble(prefix, chunks[0], chunks[1], chunks[2], chunks[3], chunks[3], finalTag), // chunk repeated
            };

            foreach (byte[] modified in modifications)
            {
                using (Stream stream = Decrypt(modified, sessionKey, out _))
                {
                    ReadUntilEnd(stream, out Exception failure);
                    Assert.That(failure, Is.InstanceOf<PgpDataValidationException>());
                }
            }
        }

        [Test]
        public void ModifiedHeaderIsRejected()
        {
            byte[] sessionKey = Plaintext(16);
            byte[] plaintext = Plaintext(100);
            byte[] seipd = EncryptSeipd(Aes, AeadAlgorithmTag.Ocb, 0, sessionKey, Plaintext(32), plaintext);
            int header = HeaderLength(seipd);

            // cipher algorithm, AEAD mode, chunk size octet, and the salt
            foreach (int offset in new[]{ 1, 2, 3, 4, 20 })
            {
                byte[] modified = Arrays.Clone(seipd);
                modified[header + offset] = (byte)(modified[header + offset] ^ 0x01);

                try
                {
                    using (Stream stream = Decrypt(modified, sessionKey, out _))
                    {
                        ReadUntilEnd(stream, out Exception failure);
                        Assert.That(failure, Is.InstanceOf<PgpDataValidationException>(), "offset " + offset);
                    }
                }
                catch (PgpException)
                {
                    // refused at the start, e.g. because of an unsupported algorithm
                }
                catch (MalformedPacketException)
                {
                }
            }
        }

        [Test]
        public void TrailingOctetsAfterFinalTagAreRejected()
        {
            byte[] sessionKey = Plaintext(16);
            byte[] seipd = EncryptSeipd(Aes, AeadAlgorithmTag.Gcm, 0, sessionKey, Plaintext(32), Plaintext(100));

            foreach (int extra in new[]{ 1, 15, 16, 17, 31, 32, 100 })
            {
                byte[] modified = FixLength(Arrays.Concatenate(seipd, Plaintext(extra)), seipd);

                using (Stream stream = Decrypt(modified, sessionKey, out PgpEncryptedData encData))
                {
                    ReadUntilEnd(stream, out Exception failure);
                    Assert.That(failure, Is.InstanceOf<PgpDataValidationException>(), "extra octets: " + extra);
                    Assert.That(encData.Verify(), Is.False);
                }
            }
        }

        [Test]
        public void RemainderShorterThanTwoTagsIsMalformed()
        {
            byte[] sessionKey = Plaintext(16);
            byte[] seipd = EncryptSeipd(Aes, AeadAlgorithmTag.Eax, 0, sessionKey, Plaintext(32), new byte[0]);

            // the data of an empty message is the final tag; add 1 to 15 octets before it, i.e. 17 to 31 octets
            int header = HeaderLength(seipd);
            byte[] prefix = Arrays.CopyOfRange(seipd, header, seipd.Length - 16);
            byte[] finalTag = Arrays.CopyOfRange(seipd, seipd.Length - 16, seipd.Length);

            for (int extra = 1; extra < 16; ++extra)
            {
                byte[] modified = PgpV6TestUtilities.NewFormatPacket(PacketTag.SymmetricEncryptedIntegrityProtected,
                    Arrays.ConcatenateAll(prefix, Plaintext(extra), finalTag));

                using (Stream stream = Decrypt(modified, sessionKey, out _))
                {
                    ReadUntilEnd(stream, out Exception failure);
                    Assert.That(failure, Is.InstanceOf<PgpDataValidationException>(), "extra octets: " + extra);
                }
            }

            // fewer than 16 octets cannot hold a final tag
            for (int length = 0; length < 16; ++length)
            {
                byte[] modified = PgpV6TestUtilities.NewFormatPacket(PacketTag.SymmetricEncryptedIntegrityProtected,
                    Arrays.Concatenate(prefix, Plaintext(length)));

                using (Stream stream = Decrypt(modified, sessionKey, out _))
                {
                    ReadUntilEnd(stream, out Exception failure);
                    Assert.That(failure, Is.InstanceOf<PgpDataValidationException>(), "length: " + length);
                }
            }
        }

        [Test]
        public void VerifyReadsTheRestOfTheMessage()
        {
            byte[] sessionKey = Plaintext(16);
            byte[] plaintext = Plaintext(300);
            byte[] seipd = EncryptSeipd(Aes, AeadAlgorithmTag.Ocb, 0, sessionKey, Plaintext(32), plaintext);

            // after reading everything
            using (Stream stream = Decrypt(seipd, sessionKey, out PgpEncryptedData encData))
            {
                Assert.That(Streams.ReadAll(stream), Is.EqualTo(plaintext));
                Assert.That(encData.Verify(), Is.True);
            }

            // before reading anything
            using (Stream stream = Decrypt(seipd, sessionKey, out PgpEncryptedData encData))
            {
                Assert.That(encData.Verify(), Is.True);
            }

            // after reading part of the message
            using (Stream stream = Decrypt(seipd, sessionKey, out PgpEncryptedData encData))
            {
                byte[] part = new byte[100];
                Assert.That(stream.Read(part, 0, part.Length), Is.GreaterThan(0));
                Assert.That(encData.Verify(), Is.True);
            }
        }

        [Test]
        public void SessionKeyLengthMustMatchCipher()
        {
            byte[] seipd = EncryptSeipd(Aes, AeadAlgorithmTag.Ocb, 0, Plaintext(16), Plaintext(32), Plaintext(10));
            PgpEncryptedData encData = ParseSingle(Arrays.Concatenate(SkeskPacket(), seipd));

            Assert.Throws<PgpException>(() => encData.InitAeadDecStream(new byte[32]));
            Assert.Throws<PgpException>(() => encData.InitAeadDecStream(new byte[15]));
        }
    }
}
