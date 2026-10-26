using System;
using System.IO;
using System.Linq;

using NUnit.Framework;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    /// <summary>Tests for the generation of version 2 SEIPD packets with version 6 SKESK packets.</summary>
    [TestFixture]
    public class PgpAeadEncryptionTest
    {
        private static readonly SecureRandom Random = new SecureRandom();
        private static readonly char[] PassPhrase = "password".ToCharArray();

        private static readonly AeadAlgorithmTag[] AeadModes = { AeadAlgorithmTag.Eax, AeadAlgorithmTag.Ocb,
            AeadAlgorithmTag.Gcm };

        private static readonly SymmetricKeyAlgorithmTag[] Ciphers =
        {
            SymmetricKeyAlgorithmTag.Aes128, SymmetricKeyAlgorithmTag.Aes192, SymmetricKeyAlgorithmTag.Aes256,
            SymmetricKeyAlgorithmTag.Camellia128, SymmetricKeyAlgorithmTag.Camellia192,
            SymmetricKeyAlgorithmTag.Camellia256, SymmetricKeyAlgorithmTag.Twofish,
        };

        private static byte[] RandomBytes(int length)
        {
            byte[] result = new byte[length];
            Random.NextBytes(result);
            return result;
        }

        /// <summary>
        /// Encrypt to the pass phrase with the given parameters; <paramref name="partial"/> selects partial body
        /// lengths for the SEIPD packet.
        /// </summary>
        internal static byte[] Encrypt(SymmetricKeyAlgorithmTag cipher, AeadAlgorithmTag aead, int chunkSizeOctet,
            byte[] plaintext, bool partial)
        {
            var generator = new PgpEncryptedDataGenerator(cipher, aead, chunkSizeOctet, Random);
            generator.AddMethod(PassPhrase, HashAlgorithmTag.Sha256);

            var bOut = new MemoryStream();
            using (Stream encOut = partial ? generator.Open(bOut, new byte[1 << 9]) : generator.Open(bOut,
                plaintext.Length))
            {
                // write in odd sized pieces
                int pos = 0;
                while (pos < plaintext.Length)
                {
                    int length = System.Math.Min(1 + Random.Next(300), plaintext.Length - pos);
                    encOut.Write(plaintext, pos, length);
                    pos += length;
                }
            }
            return bOut.ToArray();
        }

        /// <summary>
        /// Decrypt the message by recovering the session key from the first, v6 SKESK packet independently of the
        /// production code.
        /// </summary>
        internal static byte[] Decrypt(byte[] message, char[] passPhrase, out bool verified)
        {
            var skesk = (SymmetricKeyEncSessionPacket)BcpgInputStream.Wrap(new MemoryStream(message, false))
                .ReadPacket();
            Assert.That(skesk.Version, Is.EqualTo(6));

            byte[] s2kKey = PgpUtilities.MakeKeyFromPassPhrase(skesk.EncAlgorithm, skesk.S2k, passPhrase).GetKey();
            byte[] kek = PgpAead.Hkdf(s2kKey, null, skesk.GetAAData(),
                SymmetricKeyUtilities.GetKeyLengthInOctets(skesk.EncAlgorithm));
            byte[] sessionKey = PgpAead.DecryptOneShot(skesk.EncAlgorithm, skesk.AeadAlgorithm, kek, skesk.GetIV(),
                skesk.GetAAData(), Arrays.Concatenate(skesk.GetSecKeyData(), skesk.GetAuthTag()));

            var list = (PgpEncryptedDataList)new PgpObjectFactory(message).NextPgpObject();
            PgpEncryptedData encData = list[0];
            Assert.That(encData.IsAead, Is.True);

            using (Stream stream = encData.InitAeadDecStream(sessionKey))
            {
                byte[] plaintext = Streams.ReadAll(stream);
                verified = encData.Verify();
                return plaintext;
            }
        }

        [Test]
        public void EveryCipherAndAeadModeRoundTrips()
        {
            foreach (var cipher in Ciphers)
            {
                foreach (var aead in AeadModes)
                {
                    byte[] plaintext = RandomBytes(200);

                    foreach (bool partial in new[]{ false, true })
                    {
                        byte[] message = Encrypt(cipher, aead, 0, plaintext, partial);

                        Assert.That(Decrypt(message, PassPhrase, out bool verified), Is.EqualTo(plaintext),
                            $"{cipher}/{aead}/{partial}");
                        Assert.That(verified, Is.True);
                    }
                }
            }
        }

        [Test]
        public void CiphersWithSmallerBlocksAreRefused()
        {
            foreach (var cipher in new[]
            {
                SymmetricKeyAlgorithmTag.Cast5, SymmetricKeyAlgorithmTag.TripleDes, SymmetricKeyAlgorithmTag.Blowfish,
                SymmetricKeyAlgorithmTag.Idea, SymmetricKeyAlgorithmTag.Des, SymmetricKeyAlgorithmTag.Null,
            })
            {
                Assert.Throws<ArgumentException>(() => new PgpEncryptedDataGenerator(cipher, AeadAlgorithmTag.Ocb,
                    Random), cipher.ToString());
            }

            Assert.Throws<ArgumentException>(() => new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes128,
                (AeadAlgorithmTag)99, Random));
        }

        [Test]
        public void ChunkSizeOctetIsLimited()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new PgpEncryptedDataGenerator(
                SymmetricKeyAlgorithmTag.Aes128, AeadAlgorithmTag.Ocb, 17, Random));
            Assert.Throws<ArgumentOutOfRangeException>(() => new PgpEncryptedDataGenerator(
                SymmetricKeyAlgorithmTag.Aes128, AeadAlgorithmTag.Ocb, -1, Random));

            // the largest chunk size works for a short message
            byte[] plaintext = RandomBytes(1000);
            byte[] message = Encrypt(SymmetricKeyAlgorithmTag.Aes256, AeadAlgorithmTag.Gcm, 16, plaintext, false);
            Assert.That(Decrypt(message, PassPhrase, out bool verified), Is.EqualTo(plaintext));
            Assert.That(verified, Is.True);
        }

        [Test]
        public void DefiniteAndPartialLengthsDecrypt()
        {
            foreach (int chunkSizeOctet in new[]{ 0, 12 })
            {
                int chunk = 1 << (chunkSizeOctet + 6);
                foreach (int length in new[]{ 0, 1, 63, 64, 65, chunk - 1, chunk, chunk + 1, 2 * chunk, 100000 })
                {
                    byte[] plaintext = RandomBytes(length);

                    foreach (bool partial in new[]{ false, true })
                    {
                        byte[] message = Encrypt(SymmetricKeyAlgorithmTag.Aes256, AeadAlgorithmTag.Ocb, chunkSizeOctet,
                            plaintext, partial);

                        Assert.That(Decrypt(message, PassPhrase, out bool verified), Is.EqualTo(plaintext),
                            $"chunk octet {chunkSizeOctet}, length {length}, partial {partial}");
                        Assert.That(verified, Is.True);

                        if (!partial)
                        {
                            // the packet consists of the header, the salt, the chunks with their tags and the final tag
                            int chunks = (length + chunk - 1) / chunk;
                            int expectedBody = 4 + 32 + length + 16 * chunks + 16;
                            int expectedHeader = expectedBody < 192 ? 2 : expectedBody < 8384 ? 3 : 6;

                            byte[][] packets = PgpUnsupportedVersionTest.SplitPackets(message);
                            Assert.That(packets.Length, Is.EqualTo(2));
                            Assert.That(packets[1].Length, Is.EqualTo(expectedHeader + expectedBody));
                        }
                    }
                }
            }
        }

        [Test]
        public void KeysAndSaltsAreFreshAndNoEmptyChunkIsWritten()
        {
            byte[] plaintext = RandomBytes(64);
            byte[] first = Encrypt(SymmetricKeyAlgorithmTag.Aes128, AeadAlgorithmTag.Ocb, 0, plaintext, false);
            byte[] second = Encrypt(SymmetricKeyAlgorithmTag.Aes128, AeadAlgorithmTag.Ocb, 0, plaintext, false);

            byte[][] firstPackets = PgpUnsupportedVersionTest.SplitPackets(first);
            byte[][] secondPackets = PgpUnsupportedVersionTest.SplitPackets(second);

            var firstSeipd = PgpV6TestUtilities.ReadPacket<SymmetricEncIntegrityPacket>(firstPackets[1]);
            var secondSeipd = PgpV6TestUtilities.ReadPacket<SymmetricEncIntegrityPacket>(secondPackets[1]);
            Assert.That(firstSeipd.GetSalt(), Is.Not.EqualTo(secondSeipd.GetSalt()));
            Assert.That(firstPackets[0], Is.Not.EqualTo(secondPackets[0]));
            Assert.That(firstPackets[1], Is.Not.EqualTo(secondPackets[1]));

            // exactly one chunk: header 4, salt 32, chunk 64 + tag 16, final tag 16
            Assert.That(firstPackets[1].Length, Is.EqualTo(2 + 4 + 32 + 64 + 16 + 16));

            // no plaintext: only the final tag
            byte[] empty = Encrypt(SymmetricKeyAlgorithmTag.Aes128, AeadAlgorithmTag.Ocb, 0, new byte[0], false);
            Assert.That(PgpUnsupportedVersionTest.SplitPackets(empty)[1].Length, Is.EqualTo(2 + 4 + 32 + 16));
        }

        [Test]
        public void LargeMessage()
        {
            byte[] plaintext = RandomBytes(3 * 1024 * 1024 + 123);
            byte[] message = Encrypt(SymmetricKeyAlgorithmTag.Aes256, AeadAlgorithmTag.Gcm, 12, plaintext, true);

            Assert.That(Decrypt(message, PassPhrase, out bool verified), Is.EqualTo(plaintext));
            Assert.That(verified, Is.True);
        }

        /// <summary>Decrypt the first object of the message with the pass phrase, through the public API.</summary>
        private static byte[] DecryptWithPublicApi(byte[] message, char[] passPhrase, out bool verified)
        {
            var list = (PgpEncryptedDataList)new PgpObjectFactory(message).NextPgpObject();
            var encData = (PgpPbeEncryptedData)list[0];

            using (Stream stream = encData.GetDataStream(passPhrase))
            {
                byte[] plaintext = Streams.ReadAll(stream);
                verified = encData.Verify();
                return plaintext;
            }
        }

        [Test]
        public void GeneratedMessagesDecryptWithPublicApi()
        {
            foreach (var cipher in Ciphers)
            {
                foreach (var aead in AeadModes)
                {
                    byte[] plaintext = RandomBytes(300);
                    byte[] message = Encrypt(cipher, aead, 0, plaintext, partial: true);

                    var list = (PgpEncryptedDataList)new PgpObjectFactory(message).NextPgpObject();
                    var encData = (PgpPbeEncryptedData)list[0];
                    Assert.That(encData.Version, Is.EqualTo(6));
                    Assert.That(encData.Algorithm, Is.EqualTo(cipher));
                    Assert.That(encData.GetSymmetricAlgorithm(), Is.EqualTo(cipher));
                    Assert.That(encData.IsAead, Is.True);

                    Assert.That(DecryptWithPublicApi(message, PassPhrase, out bool verified), Is.EqualTo(plaintext));
                    Assert.That(verified, Is.True);
                }
            }
        }

        [Test]
        public void Argon2RoundTripForVersion6AndVersion4()
        {
            var parameters = new S2k.Argon2Params(1, 2, 10, Random);
            byte[] plaintext = RandomBytes(500);

            // version 6 SKESK with a version 2 SEIPD
            var generator = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, AeadAlgorithmTag.Ocb, Random);
            generator.AddMethod(PassPhrase, parameters);
            var bOut = new MemoryStream();
            using (Stream encOut = generator.Open(bOut, plaintext.Length))
            {
                encOut.Write(plaintext, 0, plaintext.Length);
            }

            var skesk = (SymmetricKeyEncSessionPacket)BcpgInputStream.Wrap(new MemoryStream(bOut.ToArray(), false))
                .ReadPacket();
            Assert.That(skesk.Version, Is.EqualTo(6));
            Assert.That(skesk.S2k.Type, Is.EqualTo(S2k.Argon2));
            Assert.That(skesk.S2k.Argon2Config.MemorySizeExponent, Is.EqualTo(10));
            Assert.That(skesk.S2k.Argon2Config.Parallelism, Is.EqualTo(2));
            Assert.That(skesk.S2k.Argon2Config.GetSalt(), Is.Not.EqualTo(parameters.GetSalt()));

            Assert.That(DecryptWithPublicApi(bOut.ToArray(), PassPhrase, out bool verified), Is.EqualTo(plaintext));
            Assert.That(verified, Is.True);

            // version 4 SKESK with a version 1 SEIPD (RFC 9580 A.12 shows Argon2 in a version 4 SKESK)
            var v1Generator = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, true, Random);
            v1Generator.AddMethodUtf8(PassPhrase, parameters);
            bOut = new MemoryStream();
            using (Stream encOut = v1Generator.Open(bOut, new byte[1 << 9]))
            using (Stream litOut = new PgpLiteralDataGenerator().Open(encOut, PgpLiteralData.Binary, "",
                plaintext.Length, DateTime.UtcNow))
            {
                litOut.Write(plaintext, 0, plaintext.Length);
            }

            var v4List = (PgpEncryptedDataList)new PgpObjectFactory(bOut.ToArray()).NextPgpObject();
            var v4Data = (PgpPbeEncryptedData)v4List[0];
            Assert.That(v4Data.Version, Is.EqualTo(4));
            Assert.That(v4Data.IsAead, Is.False);

            using (Stream stream = v4Data.GetDataStreamUtf8(PassPhrase))
            {
                var literal = (PgpLiteralData)new PgpObjectFactory(stream).NextPgpObject();
                Assert.That(Streams.ReadAll(literal.GetDataStream()), Is.EqualTo(plaintext));
                Assert.That(v4Data.Verify(), Is.True);
            }
        }

        [Test]
        public void WrongPassPhraseIsReportedAsDataValidationFailure()
        {
            byte[] message = Encrypt(SymmetricKeyAlgorithmTag.Aes128, AeadAlgorithmTag.Ocb, 0, RandomBytes(10),
                partial: false);
            var list = (PgpEncryptedDataList)new PgpObjectFactory(message).NextPgpObject();
            var encData = (PgpPbeEncryptedData)list[0];

            Assert.Throws<PgpDataValidationException>(() => encData.GetDataStream("other".ToCharArray()));
        }

        [Test]
        public void SessionKeyLengthMustMatchThePayloadCipher()
        {
            // the SKESK protects a 16-octet key, but the SEIPD packet uses AES-256
            var s2k = S2k.GenerateSaltedAndIterated(Random, HashAlgorithmTag.Sha256, 0x60);
            byte[] sessionKey = RandomBytes(16);
            byte[] packet = SkeskPacket(SymmetricKeyAlgorithmTag.Aes128, AeadAlgorithmTag.Ocb, s2k, sessionKey);
            byte[] seipd = PgpAeadStreamTest.EncryptSeipd(SymmetricKeyAlgorithmTag.Aes256, AeadAlgorithmTag.Ocb, 0,
                RandomBytes(32), RandomBytes(32), RandomBytes(10));

            var list = (PgpEncryptedDataList)new PgpObjectFactory(Arrays.Concatenate(packet, seipd)).NextPgpObject();
            var encData = (PgpPbeEncryptedData)list[0];

            Assert.That(encData.Algorithm, Is.EqualTo(SymmetricKeyAlgorithmTag.Aes128));
            Assert.That(encData.GetSymmetricAlgorithm(), Is.EqualTo(SymmetricKeyAlgorithmTag.Aes256));
            Assert.Throws<PgpDataValidationException>(() => encData.GetDataStream(PassPhrase));
        }

        private static byte[] SkeskPacket(SymmetricKeyAlgorithmTag cipher, AeadAlgorithmTag aead, S2k s2k,
            byte[] sessionKey)
        {
            byte[] s2kKey = PgpUtilities.MakeKeyFromPassPhrase(cipher, s2k, PassPhrase).GetKey();
            byte[] aad = SymmetricKeyEncSessionPacket.CreateAAData(6, cipher, aead);
            byte[] kek = PgpAead.Hkdf(s2kKey, null, aad, SymmetricKeyUtilities.GetKeyLengthInOctets(cipher));
            byte[] nonce = RandomBytes(AeadUtilities.GetIVLength(aead));
            byte[] encrypted = PgpAead.EncryptOneShot(cipher, aead, kek, nonce, aad, sessionKey);

            return SymmetricKeyEncSessionPacket.CreateV6Packet(cipher, aead, nonce, s2k,
                Arrays.CopyOfRange(encrypted, 0, sessionKey.Length),
                Arrays.CopyOfRange(encrypted, sessionKey.Length, encrypted.Length)).GetEncoded();
        }

        [Test]
        public void Argon2ParametersAreLimitedForVersion6SkeskToo()
        {
            // 2^30 KiB of memory would be a denial of service; the limit applies before any derivation
            var hugeMemory = new S2k.Argon2Params(new byte[16], 1, 4, 30);
            byte[] packet = SkeskPacket(SymmetricKeyAlgorithmTag.Aes128, AeadAlgorithmTag.Ocb,
                S2k.Argon2S2k(new S2k.Argon2Params(new byte[16], 1, 1, 8)), RandomBytes(16));

            // a packet with the same layout, but with the huge parameters in the S2K
            var skesk = (SymmetricKeyEncSessionPacket)BcpgInputStream.Wrap(new MemoryStream(packet, false))
                .ReadPacket();
            byte[] hugePacket = SymmetricKeyEncSessionPacket.CreateV6Packet(skesk.EncAlgorithm, skesk.AeadAlgorithm,
                skesk.GetIV(), S2k.Argon2S2k(hugeMemory), skesk.GetSecKeyData(), skesk.GetAuthTag()).GetEncoded();
            byte[] seipd = PgpAeadStreamTest.EncryptSeipd(SymmetricKeyAlgorithmTag.Aes128, AeadAlgorithmTag.Ocb, 0,
                RandomBytes(16), RandomBytes(32), RandomBytes(10));

            var list = (PgpEncryptedDataList)new PgpObjectFactory(Arrays.Concatenate(hugePacket, seipd))
                .NextPgpObject();
            var encData = (PgpPbeEncryptedData)list[0];

            var e = Assert.Throws<PgpException>(() => encData.GetDataStream(PassPhrase));
            Assert.That(e.Message, Does.Contain("out of range"));

            // the generator refuses them as well
            var generator = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes128, AeadAlgorithmTag.Ocb,
                Random);
            Assert.Throws<PgpException>(() => generator.AddMethod(PassPhrase, hugeMemory));
            Assert.Throws<ArgumentNullException>(() => generator.AddMethod(PassPhrase, (S2k.Argon2Params)null));
        }

        /// <summary>RFC 9580 9.5: no deprecated hash for the key derivation in version 6 packets.</summary>
        [Test]
        public void WeakS2kHashInVersion6SkeskIsRefusedWhenDecrypting()
        {
            foreach (var hash in new[]{ HashAlgorithmTag.MD5, HashAlgorithmTag.Sha1, HashAlgorithmTag.RipeMD160 })
            {
                var s2k = S2k.GenerateSaltedAndIterated(Random, hash, 0x60);
                byte[] packet = SkeskPacket(SymmetricKeyAlgorithmTag.Aes128, AeadAlgorithmTag.Ocb, s2k, RandomBytes(16));
                byte[] seipd = PgpAeadStreamTest.EncryptSeipd(SymmetricKeyAlgorithmTag.Aes128, AeadAlgorithmTag.Ocb, 0,
                    RandomBytes(16), RandomBytes(32), RandomBytes(10));

                var list = (PgpEncryptedDataList)new PgpObjectFactory(Arrays.Concatenate(packet, seipd))
                    .NextPgpObject();
                var encData = (PgpPbeEncryptedData)list[0];

                Assert.Throws<PgpDataValidationException>(() => encData.GetDataStream(PassPhrase), hash.ToString());
            }
        }

        [TestCase("a9-eax-message.asc")]
        [TestCase("a10-ocb-message.asc")]
        [TestCase("a11-gcm-message.asc")]
        public void Rfc9580Messages(string file)
        {
            byte[] message = PgpV6TestUtilities.LoadRfc9580(file);
            var list = (PgpEncryptedDataList)new PgpObjectFactory(message).NextPgpObject();
            var encData = (PgpPbeEncryptedData)list[0];

            Assert.That(encData.Version, Is.EqualTo(6));
            Assert.That(encData.IsAead, Is.True);
            Assert.That(encData.GetSymmetricAlgorithm(), Is.EqualTo(SymmetricKeyAlgorithmTag.Aes128));

            using (Stream stream = encData.GetDataStream("password".ToCharArray()))
            {
                var factory = new PgpObjectFactory(stream);
                var literal = (PgpLiteralData)factory.NextPgpObject();
                Assert.That(Strings.FromUtf8ByteArray(Streams.ReadAll(literal.GetDataStream())),
                    Is.EqualTo("Hello, world!"));
                Assert.That(factory.NextPgpObject(), Is.InstanceOf<PgpPadding>());
                Assert.That(factory.NextPgpObject(), Is.Null);
                Assert.That(encData.Verify(), Is.True);
            }
        }

        [Test]
        public void WeakS2kHashesAreRefused()
        {
            var generator = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes128, AeadAlgorithmTag.Ocb, Random);

            foreach (var hash in new[]{ HashAlgorithmTag.MD5, HashAlgorithmTag.Sha1, HashAlgorithmTag.RipeMD160 })
            {
                Assert.Throws<ArgumentException>(() => generator.AddMethod(PassPhrase, hash), hash.ToString());
            }

            generator.AddMethod(PassPhrase, HashAlgorithmTag.Sha256);
            generator.AddMethod(PassPhrase, HashAlgorithmTag.Sha512);
        }

        [Test]
        public void OpenRequiresAMethod()
        {
            var generator = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes128, AeadAlgorithmTag.Ocb, Random);

            Assert.Throws<InvalidOperationException>(() => generator.Open(new MemoryStream(), 10));
        }

        [Test]
        public void WrongPassPhraseCannotRecoverSessionKey()
        {
            byte[] message = Encrypt(SymmetricKeyAlgorithmTag.Aes128, AeadAlgorithmTag.Ocb, 0, RandomBytes(10), false);

            Assert.Catch<Exception>(() => Decrypt(message, "other".ToCharArray(), out _));
        }
    }
}
