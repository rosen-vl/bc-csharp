using System;
using System.Collections.Generic;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    /// <summary>
    /// Cross-checks of v2 SEIPD, v6 SKESK and v6 PKESK against an independent implementation written from RFC 9580
    /// and RFC 9980 with the lightweight primitives only. No OpenPGP helper of the library is used on the independent
    /// side, so a mistake shared by the library's encrypting and decrypting code (a nonce layout, a key derivation, an
    /// associated data octet) cannot cancel itself out. The RFC vectors only cover one chunk; these tests cover many.
    /// </summary>
    [TestFixture]
    public class PgpAeadIndependentTest
    {
        private static readonly SecureRandom Random = new SecureRandom();

        private const int TagLength = 16;
        private const int SaltLength = 32;

        #region Independent implementation (RFC 9580 5.13.2, 5.3.2, 5.1.2, 5.1.6; RFC 9980 4.2)

        private static IBlockCipher Engine(SymmetricKeyAlgorithmTag cipher)
        {
            switch (cipher)
            {
            case SymmetricKeyAlgorithmTag.Aes128:
            case SymmetricKeyAlgorithmTag.Aes192:
            case SymmetricKeyAlgorithmTag.Aes256:
                return new AesEngine();
            case SymmetricKeyAlgorithmTag.Camellia128:
            case SymmetricKeyAlgorithmTag.Camellia192:
            case SymmetricKeyAlgorithmTag.Camellia256:
                return new CamelliaEngine();
            case SymmetricKeyAlgorithmTag.Twofish:
                return new TwofishEngine();
            default:
                throw new ArgumentException("not a 128-bit block cipher", nameof(cipher));
            }
        }

        private static int KeyLength(SymmetricKeyAlgorithmTag cipher)
        {
            switch (cipher)
            {
            case SymmetricKeyAlgorithmTag.Aes128:
            case SymmetricKeyAlgorithmTag.Camellia128:
                return 16;
            case SymmetricKeyAlgorithmTag.Aes192:
            case SymmetricKeyAlgorithmTag.Camellia192:
                return 24;
            default:
                return 32;
            }
        }

        private static int NonceLength(AeadAlgorithmTag aead) =>
            aead == AeadAlgorithmTag.Eax ? 16 : aead == AeadAlgorithmTag.Ocb ? 15 : 12;

        private static IAeadCipher AeadCipher(SymmetricKeyAlgorithmTag cipher, AeadAlgorithmTag aead)
        {
            switch (aead)
            {
            case AeadAlgorithmTag.Eax:
                return new EaxBlockCipher(Engine(cipher));
            case AeadAlgorithmTag.Ocb:
                return new OcbBlockCipher(Engine(cipher), Engine(cipher));
            default:
                return new GcmBlockCipher(Engine(cipher));
            }
        }

        private static byte[] Hkdf(IDigest digest, byte[] ikm, byte[] salt, byte[] info, int length)
        {
            var hkdf = new HkdfBytesGenerator(digest);
            hkdf.Init(new HkdfParameters(ikm, salt, info));
            byte[] output = new byte[length];
            hkdf.GenerateBytes(output, 0, length);
            return output;
        }

        /// <summary>AEAD encryption or decryption of a whole buffer (throws on a failed tag).</summary>
        private static byte[] Aead(bool encrypt, SymmetricKeyAlgorithmTag cipher, AeadAlgorithmTag aead, byte[] key,
            byte[] nonce, byte[] ad, byte[] input, int offset, int length)
        {
            IAeadCipher c = AeadCipher(cipher, aead);
            c.Init(encrypt, new AeadParameters(new KeyParameter(key), TagLength * 8, nonce, ad));
            byte[] output = new byte[c.GetOutputSize(length)];
            int n = c.ProcessBytes(input, offset, length, output, 0);
            n += c.DoFinal(output, n);
            return Arrays.CopyOfRange(output, 0, n);
        }

        /// <summary>The nonce: the IV (N - 64 bits) followed by the big-endian 64-bit chunk index.</summary>
        private static byte[] ChunkNonce(byte[] iv, long index)
        {
            byte[] nonce = new byte[iv.Length + 8];
            Array.Copy(iv, nonce, iv.Length);
            for (int i = 0; i < 8; ++i)
            {
                nonce[iv.Length + i] = (byte)(index >> (56 - 8 * i));
            }
            return nonce;
        }

        private static byte[] SeipdAd(SymmetricKeyAlgorithmTag cipher, AeadAlgorithmTag aead, int c) =>
            new byte[]{ 0xD2, 0x02, (byte)cipher, (byte)aead, (byte)c };

        private static void DeriveMessageKey(SymmetricKeyAlgorithmTag cipher, AeadAlgorithmTag aead, int c,
            byte[] sessionKey, byte[] salt, out byte[] key, out byte[] iv)
        {
            int keyLength = KeyLength(cipher), ivLength = NonceLength(aead) - 8;
            byte[] okm = Hkdf(new Sha256Digest(), sessionKey, salt, SeipdAd(cipher, aead, c), keyLength + ivLength);
            key = Arrays.CopyOfRange(okm, 0, keyLength);
            iv = Arrays.CopyOfRange(okm, keyLength, okm.Length);
        }

        /// <summary>
        /// The encrypted chunks followed by the final tag (the SEIPD body after the 36-octet header).
        /// </summary>
        private static byte[] EncryptChunks(SymmetricKeyAlgorithmTag cipher, AeadAlgorithmTag aead, int c,
            byte[] key, byte[] iv, byte[] plaintext)
        {
            byte[] ad = SeipdAd(cipher, aead, c);
            int chunkLength = 1 << (c + 6);
            var output = new MemoryStream();
            long index = 0;
            for (int pos = 0; pos < plaintext.Length; pos += chunkLength)
            {
                int length = System.Math.Min(chunkLength, plaintext.Length - pos);
                byte[] chunk = Aead(true, cipher, aead, key, ChunkNonce(iv, index++), ad, plaintext, pos, length);
                output.Write(chunk, 0, chunk.Length);
            }
            byte[] finalAd = new byte[ad.Length + 8];
            Array.Copy(ad, finalAd, ad.Length);
            for (int i = 0; i < 8; ++i)
            {
                finalAd[ad.Length + i] = (byte)((long)plaintext.Length >> (56 - 8 * i));
            }
            byte[] tag = Aead(true, cipher, aead, key, ChunkNonce(iv, index), finalAd, new byte[0], 0, 0);
            output.Write(tag, 0, tag.Length);
            return output.ToArray();
        }

        /// <summary>Decrypt the chunks and check the final tag; throws if anything does not authenticate.</summary>
        private static byte[] DecryptChunks(SymmetricKeyAlgorithmTag cipher, AeadAlgorithmTag aead, int c,
            byte[] key, byte[] iv, byte[] data)
        {
            byte[] ad = SeipdAd(cipher, aead, c);
            int chunkLength = 1 << (c + 6);
            int end = data.Length - TagLength;
            Assert.That(end, Is.GreaterThanOrEqualTo(0), "no final tag");

            var plaintext = new MemoryStream();
            long index = 0;
            for (int pos = 0; pos < end; pos += chunkLength + TagLength)
            {
                int length = System.Math.Min(chunkLength + TagLength, end - pos);
                byte[] chunk = Aead(false, cipher, aead, key, ChunkNonce(iv, index++), ad, data, pos, length);
                plaintext.Write(chunk, 0, chunk.Length);
            }
            byte[] finalAd = new byte[ad.Length + 8];
            Array.Copy(ad, finalAd, ad.Length);
            for (int i = 0; i < 8; ++i)
            {
                finalAd[ad.Length + i] = (byte)(plaintext.Length >> (56 - 8 * i));
            }
            Aead(false, cipher, aead, key, ChunkNonce(iv, index), finalAd, data, end, TagLength);
            return plaintext.ToArray();
        }

        private static byte[] SeipdBody(SymmetricKeyAlgorithmTag cipher, AeadAlgorithmTag aead, int c,
            byte[] sessionKey, byte[] salt, byte[] plaintext)
        {
            DeriveMessageKey(cipher, aead, c, sessionKey, salt, out byte[] key, out byte[] iv);
            return Arrays.ConcatenateAll(new byte[]{ 2, (byte)cipher, (byte)aead, (byte)c }, salt,
                EncryptChunks(cipher, aead, c, key, iv, plaintext));
        }

        private static byte[] DecryptSeipdBody(byte[] body, byte[] sessionKey)
        {
            Assert.That(body[0], Is.EqualTo(2));
            var cipher = (SymmetricKeyAlgorithmTag)body[1];
            var aead = (AeadAlgorithmTag)body[2];
            int c = body[3];
            byte[] salt = Arrays.CopyOfRange(body, 4, 4 + SaltLength);
            Assert.That(sessionKey.Length, Is.EqualTo(KeyLength(cipher)));
            DeriveMessageKey(cipher, aead, c, sessionKey, salt, out byte[] key, out byte[] iv);
            return DecryptChunks(cipher, aead, c, key, iv, Arrays.CopyOfRange(body, 4 + SaltLength, body.Length));
        }

        /// <summary>Iterated and salted S2K (RFC 9580 3.7.1.3).</summary>
        private static byte[] IteratedS2k(HashAlgorithmTag hash, byte[] salt, int codedCount, byte[] passPhrase,
            int keyLength)
        {
            long count = (16L + (codedCount & 15)) << ((codedCount >> 4) + 6);
            byte[] input = Arrays.Concatenate(salt, passPhrase);
            count = System.Math.Max(count, input.Length);

            var key = new MemoryStream();
            for (int preload = 0; key.Length < keyLength; ++preload)
            {
                IDigest digest = hash == HashAlgorithmTag.Sha256 ? (IDigest)new Sha256Digest() : new Sha512Digest();
                for (int i = 0; i < preload; ++i)
                {
                    digest.Update(0);
                }
                long remaining = count;
                while (remaining > 0)
                {
                    int n = (int)System.Math.Min(remaining, input.Length);
                    digest.BlockUpdate(input, 0, n);
                    remaining -= n;
                }
                byte[] block = new byte[digest.GetDigestSize()];
                digest.DoFinal(block, 0);
                key.Write(block, 0, block.Length);
            }
            return Arrays.CopyOfRange(key.ToArray(), 0, keyLength);
        }

        private static byte[] SkeskAd(SymmetricKeyAlgorithmTag cipher, AeadAlgorithmTag aead) =>
            new byte[]{ 0xC3, 0x06, (byte)cipher, (byte)aead };

        /// <summary>Recover the session key from the body of a v6 SKESK that uses an iterated and salted S2K.</summary>
        private static byte[] DecryptSkeskV6(byte[] body, byte[] passPhrase)
        {
            Assert.That(body[0], Is.EqualTo(6));
            int count = body[1];
            var cipher = (SymmetricKeyAlgorithmTag)body[2];
            var aead = (AeadAlgorithmTag)body[3];
            int s2kLength = body[4];
            Assert.That(count, Is.EqualTo(3 + s2kLength + NonceLength(aead)), "count of the following fields");

            // S2K specifier: type 3, hash, 8-octet salt, coded count
            Assert.That(s2kLength, Is.EqualTo(11));
            Assert.That(body[5], Is.EqualTo(3));
            var hash = (HashAlgorithmTag)body[6];
            byte[] salt = Arrays.CopyOfRange(body, 7, 15);
            int codedCount = body[15];

            byte[] nonce = Arrays.CopyOfRange(body, 16, 16 + NonceLength(aead));
            int pos = 16 + nonce.Length;

            byte[] ikm = IteratedS2k(hash, salt, codedCount, passPhrase, KeyLength(cipher));
            byte[] kek = Hkdf(new Sha256Digest(), ikm, null, SkeskAd(cipher, aead), KeyLength(cipher));
            return Aead(false, cipher, aead, kek, nonce, SkeskAd(cipher, aead), body, pos, body.Length - pos);
        }

        private static byte[] SkeskV6Body(SymmetricKeyAlgorithmTag cipher, AeadAlgorithmTag aead, byte[] passPhrase,
            byte[] sessionKey)
        {
            byte[] salt = SecureRandom.GetNextBytes(Random, 8);
            const int codedCount = 0x60;
            byte[] nonce = SecureRandom.GetNextBytes(Random, NonceLength(aead));
            byte[] ikm = IteratedS2k(HashAlgorithmTag.Sha256, salt, codedCount, passPhrase, KeyLength(cipher));
            byte[] kek = Hkdf(new Sha256Digest(), ikm, null, SkeskAd(cipher, aead), KeyLength(cipher));
            byte[] encrypted = Aead(true, cipher, aead, kek, nonce, SkeskAd(cipher, aead), sessionKey, 0,
                sessionKey.Length);

            byte[] s2k = Arrays.ConcatenateAll(new byte[]{ 3, (byte)HashAlgorithmTag.Sha256 }, salt,
                new byte[]{ codedCount });
            return Arrays.ConcatenateAll(
                new byte[]{ 6, (byte)(3 + s2k.Length + nonce.Length), (byte)cipher, (byte)aead, (byte)s2k.Length },
                s2k, nonce, encrypted);
        }

        /// <summary>X25519 session key encryption (RFC 9580 5.1.6) for a v6 PKESK: eph || len || C.</summary>
        private static byte[] X25519Fields(byte[] recipientPublicKey, byte[] sessionKey)
        {
            var ephemeral = new X25519PrivateKeyParameters(Random);
            byte[] ephemeralPublic = ephemeral.GeneratePublicKey().GetEncoded();
            byte[] shared = new byte[32];
            ephemeral.GenerateSecret(new X25519PublicKeyParameters(recipientPublicKey), shared, 0);

            byte[] kek = Hkdf(new Sha256Digest(), Arrays.ConcatenateAll(ephemeralPublic, recipientPublicKey, shared),
                null, Strings.ToByteArray("OpenPGP X25519"), 16);
            var wrapper = new AesWrapEngine();
            wrapper.Init(true, new KeyParameter(kek));
            byte[] wrapped = wrapper.Wrap(sessionKey, 0, sessionKey.Length);
            return Arrays.ConcatenateAll(ephemeralPublic, new byte[]{ (byte)wrapped.Length }, wrapped);
        }

        private static byte[] X25519Decrypt(byte[] fields, byte[] recipientSecret, byte[] recipientPublicKey)
        {
            byte[] ephemeralPublic = Arrays.CopyOfRange(fields, 0, 32);
            int length = fields[32];
            Assert.That(fields.Length, Is.EqualTo(33 + length), "v6: the length counts only the wrapped key");
            byte[] shared = new byte[32];
            new X25519PrivateKeyParameters(recipientSecret)
                .GenerateSecret(new X25519PublicKeyParameters(ephemeralPublic), shared, 0);
            byte[] kek = Hkdf(new Sha256Digest(), Arrays.ConcatenateAll(ephemeralPublic, recipientPublicKey, shared),
                null, Strings.ToByteArray("OpenPGP X25519"), 16);
            var wrapper = new AesWrapEngine();
            wrapper.Init(false, new KeyParameter(kek));
            return wrapper.Unwrap(fields, 33, length);
        }

        /// <summary>ML-KEM-768+X25519 session key encryption (RFC 9980 4.2.3) for a v6 PKESK.</summary>
        private static byte[] MLKem768X25519Fields(MLKem768X25519PublicKeyParameters recipient, byte[] sessionKey)
        {
            var ephemeral = new X25519PrivateKeyParameters(Random);
            byte[] ecdhCipherText = ephemeral.GeneratePublicKey().GetEncoded();
            byte[] ecdhShare = new byte[32];
            ephemeral.GenerateSecret(recipient.X25519Key, ecdhShare, 0);

            var encapsulator = new MLKemEncapsulator(MLKemParameters.ml_kem_768);
            encapsulator.Init(new ParametersWithRandom(recipient.MLKemKey, Random));
            byte[] mlkemCipherText = new byte[encapsulator.EncapsulationLength];
            byte[] mlkemShare = new byte[encapsulator.SecretLength];
            encapsulator.Encapsulate(mlkemCipherText, 0, mlkemCipherText.Length, mlkemShare, 0, mlkemShare.Length);

            var sha3 = new Sha3Digest(256);
            byte[] domSep = Strings.ToByteArray("OpenPGPCompositeKDFv1");
            byte[] combinerInput = Arrays.ConcatenateAll(mlkemShare, ecdhShare, ecdhCipherText,
                recipient.X25519Key.GetEncoded(), new byte[]{ 35 }, domSep, new byte[]{ (byte)domSep.Length });
            sha3.BlockUpdate(combinerInput, 0, combinerInput.Length);
            byte[] kek = new byte[32];
            sha3.DoFinal(kek, 0);

            var wrapper = new AesWrapEngine();
            wrapper.Init(true, new KeyParameter(kek));
            byte[] wrapped = wrapper.Wrap(sessionKey, 0, sessionKey.Length);
            return Arrays.ConcatenateAll(ecdhCipherText, mlkemCipherText, new byte[]{ (byte)wrapped.Length }, wrapped);
        }

        /// <summary>A v6 PKESK body: 6, n, key version, fingerprint, algorithm, fields (RFC 9580 5.1.2).</summary>
        private static byte[] PkeskV6Body(PgpPublicKey recipient, byte[] fields)
        {
            byte[] fingerprint = recipient.GetFingerprint();
            return Arrays.ConcatenateAll(
                new byte[]{ 6, (byte)(1 + fingerprint.Length), (byte)recipient.Version }, fingerprint,
                new byte[]{ (byte)recipient.Algorithm }, fields);
        }

        /// <summary>A literal data packet body: binary format, empty file name, zero date.</summary>
        private static byte[] LiteralBody(byte[] content) =>
            Arrays.Concatenate(new byte[]{ (byte)'b', 0, 0, 0, 0, 0 }, content);

        private static byte[] Packet(PacketTag tag, byte[] body) => PgpV6TestUtilities.NewFormatPacket(tag, body);

        /// <summary>Split a packet sequence into (tag, body) pairs, joining partial body lengths.</summary>
        private static List<KeyValuePair<int, byte[]>> ReadPackets(byte[] data)
        {
            var packets = new List<KeyValuePair<int, byte[]>>();
            int pos = 0;
            while (pos < data.Length)
            {
                int header = data[pos++];
                Assert.That(header & 0xC0, Is.EqualTo(0xC0), "new packet format expected");
                int tag = header & 0x3F;
                var body = new MemoryStream();
                while (true)
                {
                    int first = data[pos++];
                    int length;
                    bool partial = false;
                    if (first < 192)
                    {
                        length = first;
                    }
                    else if (first < 224)
                    {
                        length = ((first - 192) << 8) + data[pos++] + 192;
                    }
                    else if (first == 255)
                    {
                        length = (data[pos] << 24) | (data[pos + 1] << 16) | (data[pos + 2] << 8) | data[pos + 3];
                        pos += 4;
                    }
                    else
                    {
                        length = 1 << (first & 0x1F);
                        partial = true;
                    }
                    body.Write(data, pos, length);
                    pos += length;
                    if (!partial)
                    {
                        break;
                    }
                }
                packets.Add(new KeyValuePair<int, byte[]>(tag, body.ToArray()));
            }
            return packets;
        }

        /// <summary>The content of the literal data packet that a decrypted message consists of.</summary>
        private static byte[] LiteralContent(byte[] plaintext)
        {
            var packets = ReadPackets(plaintext);
            Assert.That(packets[0].Key, Is.EqualTo((int)PacketTag.LiteralData));
            byte[] body = packets[0].Value;
            int nameLength = body[1];
            return Arrays.CopyOfRange(body, 2 + nameLength + 4, body.Length);
        }

        #endregion

        private static readonly AeadAlgorithmTag[] Modes =
            { AeadAlgorithmTag.Eax, AeadAlgorithmTag.Ocb, AeadAlgorithmTag.Gcm };

        private static IEnumerable<TestCaseData> StreamCases()
        {
            int[] chunkOctets = { 0, 1, 6 };
            foreach (AeadAlgorithmTag aead in Modes)
            {
                foreach (int c in chunkOctets)
                {
                    int chunk = 1 << (c + 6);
                    foreach (int length in new[]{ 0, 1, chunk - 1, chunk, chunk + 1, 2 * chunk, 3 * chunk + 17 })
                    {
                        yield return new TestCaseData(aead, c, length).SetName(
                            $"{{m}}({aead},c={c},{length})");
                    }
                }
            }
        }

        private static readonly SymmetricKeyAlgorithmTag[] Ciphers =
        {
            SymmetricKeyAlgorithmTag.Aes128, SymmetricKeyAlgorithmTag.Aes192, SymmetricKeyAlgorithmTag.Aes256,
            SymmetricKeyAlgorithmTag.Camellia128, SymmetricKeyAlgorithmTag.Camellia256,
            SymmetricKeyAlgorithmTag.Twofish,
        };

        private static SymmetricKeyAlgorithmTag CipherFor(int length) => Ciphers[length % Ciphers.Length];

        /// <summary>
        /// The library's encrypting stream produces exactly what the independent implementation does.
        /// </summary>
        [TestCaseSource(nameof(StreamCases))]
        public void EncryptingStreamMatchesIndependentImplementation(AeadAlgorithmTag aead, int c, int length)
        {
            SymmetricKeyAlgorithmTag cipher = CipherFor(length);
            byte[] key = SecureRandom.GetNextBytes(Random, KeyLength(cipher));
            byte[] iv = SecureRandom.GetNextBytes(Random, NonceLength(aead) - 8);
            byte[] plaintext = SecureRandom.GetNextBytes(Random, length);

            var output = new MemoryStream();
            var stream = new PgpAeadOutputStream(output, cipher, aead, key, Arrays.Concatenate(iv, new byte[8]),
                SeipdAd(cipher, aead, c), c);
            // write in odd pieces, so that chunk boundaries fall inside writes
            for (int pos = 0; pos < length; pos += 7)
            {
                stream.Write(plaintext, pos, System.Math.Min(7, length - pos));
            }
            stream.Finish();

            Assert.That(output.ToArray(), Is.EqualTo(EncryptChunks(cipher, aead, c, key, iv, plaintext)));
        }

        /// <summary>The library's decrypting stream reads what the independent implementation produces.</summary>
        [TestCaseSource(nameof(StreamCases))]
        public void DecryptingStreamReadsIndependentImplementation(AeadAlgorithmTag aead, int c, int length)
        {
            SymmetricKeyAlgorithmTag cipher = CipherFor(length + 1);
            byte[] key = SecureRandom.GetNextBytes(Random, KeyLength(cipher));
            byte[] iv = SecureRandom.GetNextBytes(Random, NonceLength(aead) - 8);
            byte[] plaintext = SecureRandom.GetNextBytes(Random, length);
            byte[] encrypted = EncryptChunks(cipher, aead, c, key, iv, plaintext);

            using (var stream = new PgpAeadInputStream(new MemoryStream(encrypted, false), cipher, aead, key,
                Arrays.Concatenate(iv, new byte[8]), SeipdAd(cipher, aead, c), c))
            {
                Assert.That(Streams.ReadAll(stream), Is.EqualTo(plaintext));
                Assert.That(stream.IsVerified, Is.True);
            }
        }

        /// <summary>
        /// Chunk indexes that need three octets: 64-octet chunks over 4 MiB of data (65,600 chunks). A mistake in the
        /// higher octets of the nonce would not show with the RFC vectors (one chunk) or with small messages.
        /// </summary>
        [Test]
        public void ChunkIndexesBeyondTwoOctets()
        {
            const int c = 0;
            const SymmetricKeyAlgorithmTag cipher = SymmetricKeyAlgorithmTag.Aes128;
            const AeadAlgorithmTag aead = AeadAlgorithmTag.Gcm;
            byte[] key = SecureRandom.GetNextBytes(Random, 16);
            byte[] iv = SecureRandom.GetNextBytes(Random, NonceLength(aead) - 8);
            byte[] plaintext = SecureRandom.GetNextBytes(Random, 65600 * 64 + 5);

            var output = new MemoryStream();
            var encryptor = new PgpAeadOutputStream(output, cipher, aead, key, Arrays.Concatenate(iv, new byte[8]),
                SeipdAd(cipher, aead, c), c);
            encryptor.Write(plaintext, 0, plaintext.Length);
            encryptor.Finish();

            byte[] encrypted = output.ToArray();
            Assert.That(DecryptChunks(cipher, aead, c, key, iv, encrypted), Is.EqualTo(plaintext));

            using (var decryptor = new PgpAeadInputStream(new MemoryStream(encrypted, false), cipher, aead, key,
                Arrays.Concatenate(iv, new byte[8]), SeipdAd(cipher, aead, c), c))
            {
                Assert.That(Streams.ReadAll(decryptor), Is.EqualTo(plaintext));
            }
        }

        /// <summary>
        /// A whole message from the public generator (v6 SKESK + v2 SEIPD, partial lengths) decrypts with the
        /// independent implementation: S2K, HKDF of the SKESK, AEAD of the session key, HKDF of the SEIPD, chunks.
        /// </summary>
        [Test]
        public void GeneratedPassPhraseMessageDecryptsIndependently(
            [ValueSource(nameof(Modes))] AeadAlgorithmTag aead,
            [Values(SymmetricKeyAlgorithmTag.Aes128, SymmetricKeyAlgorithmTag.Aes256,
                SymmetricKeyAlgorithmTag.Camellia192)] SymmetricKeyAlgorithmTag cipher,
            [Values(0, 2)] int c)
        {
            byte[] passPhrase = Strings.ToUtf8ByteArray("independent pass phrase");
            byte[] content = SecureRandom.GetNextBytes(Random, 3 * (1 << (c + 6)) + 11);

            var generator = new PgpEncryptedDataGenerator(cipher, aead, c, Random);
            generator.AddMethodRaw(passPhrase, HashAlgorithmTag.Sha256, 0x60);
            var message = new MemoryStream();
            using (Stream encrypted = generator.Open(message, new byte[256]))
            using (Stream literal = new PgpLiteralDataGenerator().Open(encrypted, PgpLiteralData.Binary, "",
                content.Length, DateTime.UtcNow))
            {
                literal.Write(content, 0, content.Length);
            }

            var packets = ReadPackets(message.ToArray());
            Assert.That(packets.Count, Is.EqualTo(2));
            Assert.That(packets[0].Key, Is.EqualTo((int)PacketTag.SymmetricKeyEncryptedSessionKey));
            Assert.That(packets[1].Key, Is.EqualTo((int)PacketTag.SymmetricEncryptedIntegrityProtected));

            byte[] sessionKey = DecryptSkeskV6(packets[0].Value, passPhrase);
            Assert.That(sessionKey.Length, Is.EqualTo(KeyLength(cipher)));
            byte[] seipd = packets[1].Value;
            Assert.That(seipd[1], Is.EqualTo((byte)cipher));
            Assert.That(seipd[2], Is.EqualTo((byte)aead));
            Assert.That(seipd[3], Is.EqualTo((byte)c));

            Assert.That(LiteralContent(DecryptSeipdBody(seipd, sessionKey)), Is.EqualTo(content));
        }

        /// <summary>A message built by the independent implementation decrypts with the public API.</summary>
        [Test]
        public void IndependentPassPhraseMessageDecryptsWithPublicApi(
            [ValueSource(nameof(Modes))] AeadAlgorithmTag aead,
            [Values(0, 3)] int c)
        {
            const SymmetricKeyAlgorithmTag cipher = SymmetricKeyAlgorithmTag.Aes256;
            byte[] passPhrase = Strings.ToUtf8ByteArray("another pass phrase");
            byte[] content = SecureRandom.GetNextBytes(Random, 5 * (1 << (c + 6)) + 3);
            byte[] sessionKey = SecureRandom.GetNextBytes(Random, 32);
            byte[] salt = SecureRandom.GetNextBytes(Random, SaltLength);

            byte[] message = Arrays.Concatenate(
                Packet(PacketTag.SymmetricKeyEncryptedSessionKey, SkeskV6Body(cipher, aead, passPhrase, sessionKey)),
                Packet(PacketTag.SymmetricEncryptedIntegrityProtected, SeipdBody(cipher, aead, c, sessionKey, salt,
                    Packet(PacketTag.LiteralData, LiteralBody(content)))));

            var list = (PgpEncryptedDataList)new PgpObjectFactory(message).NextPgpObject();
            var pbe = (PgpPbeEncryptedData)list[0];
            Assert.That(pbe.Version, Is.EqualTo(6));
            Assert.That(pbe.GetSymmetricAlgorithm(), Is.EqualTo(cipher));
            Stream decrypted = pbe.GetDataStreamRaw(passPhrase);
            var literal = (PgpLiteralData)new PgpObjectFactory(decrypted).NextPgpObject();
            Assert.That(Streams.ReadAll(literal.GetDataStream()), Is.EqualTo(content));
            Assert.That(pbe.Verify(), Is.True);
        }

        /// <summary>A v6 PKESK for an X25519 key, both directions (RFC 9580 5.1.2, 5.1.6).</summary>
        [Test]
        public void X25519Version6PkeskBothDirections([Values(4, 6)] int keyVersion)
        {
            var pair = new PgpKeyPair(keyVersion, PublicKeyAlgorithmTag.X25519,
                PgpV6KeyGenerationTest.GenerateX(PublicKeyAlgorithmTag.X25519), DateTime.UtcNow);
            byte[] recipientPublic = ((X25519PublicBcpgKey)pair.PublicKey.PublicKeyPacket.Key).GetKey();
            byte[] recipientSecret = ((X25519PrivateKeyParameters)pair.PrivateKey.Key).GetEncoded();
            byte[] content = SecureRandom.GetNextBytes(Random, 1000);

            // independent -> library
            byte[] sessionKey = SecureRandom.GetNextBytes(Random, 16);
            byte[] message = Arrays.Concatenate(
                Packet(PacketTag.PublicKeyEncryptedSession,
                    PkeskV6Body(pair.PublicKey, X25519Fields(recipientPublic, sessionKey))),
                Packet(PacketTag.SymmetricEncryptedIntegrityProtected,
                    SeipdBody(SymmetricKeyAlgorithmTag.Aes128, AeadAlgorithmTag.Ocb, 1, sessionKey,
                        SecureRandom.GetNextBytes(Random, SaltLength),
                        Packet(PacketTag.LiteralData, LiteralBody(content)))));
            Assert.That(DecryptWithLibrary(message, pair.PrivateKey), Is.EqualTo(content));

            // library -> independent
            var generator = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes192, AeadAlgorithmTag.Eax, 1,
                Random);
            generator.AddMethod(pair.PublicKey);
            byte[] generated = EncryptWithLibrary(generator, content);
            var packets = ReadPackets(generated);
            byte[] pkesk = packets[0].Value;
            Assert.That(pkesk[0], Is.EqualTo(6));
            Assert.That(pkesk[1], Is.EqualTo(1 + pair.PublicKey.GetFingerprint().Length));
            Assert.That(pkesk[2], Is.EqualTo(keyVersion));
            Assert.That(Arrays.CopyOfRange(pkesk, 3, 3 + pkesk[1] - 1), Is.EqualTo(pair.PublicKey.GetFingerprint()));
            int fieldsPos = 2 + pkesk[1];
            Assert.That(pkesk[fieldsPos], Is.EqualTo((byte)PublicKeyAlgorithmTag.X25519));
            byte[] recovered = X25519Decrypt(Arrays.CopyOfRange(pkesk, fieldsPos + 1, pkesk.Length), recipientSecret,
                recipientPublic);
            Assert.That(recovered.Length, Is.EqualTo(24), "AES-192 session key, raw, no checksum");
            Assert.That(LiteralContent(DecryptSeipdBody(packets[1].Value, recovered)), Is.EqualTo(content));
        }

        /// <summary>
        /// A v6 PKESK for ML-KEM-768+X25519 built independently (no symmetric algorithm octet; the length counts only
        /// the wrapped key) decrypts with the library, for both key versions that allow algorithm 35.
        /// </summary>
        [Test]
        public void MLKem768X25519Version6PkeskFromIndependentImplementation([Values(4, 6)] int keyVersion)
        {
            var privateKey = new MLKem768X25519PrivateKeyParameters(Random);
            var pair = new PgpKeyPair(keyVersion, PublicKeyAlgorithmTag.MLKem768_X25519, privateKey.GeneratePublicKey(),
                privateKey, DateTime.UtcNow);
            byte[] content = SecureRandom.GetNextBytes(Random, 333);
            byte[] sessionKey = SecureRandom.GetNextBytes(Random, 32);

            byte[] fields = MLKem768X25519Fields(privateKey.GeneratePublicKey(), sessionKey);
            byte[] message = Arrays.Concatenate(
                Packet(PacketTag.PublicKeyEncryptedSession, PkeskV6Body(pair.PublicKey, fields)),
                Packet(PacketTag.SymmetricEncryptedIntegrityProtected,
                    SeipdBody(SymmetricKeyAlgorithmTag.Aes256, AeadAlgorithmTag.Gcm, 0, sessionKey,
                        SecureRandom.GetNextBytes(Random, SaltLength),
                        Packet(PacketTag.LiteralData, LiteralBody(content)))));

            Assert.That(DecryptWithLibrary(message, pair.PrivateKey), Is.EqualTo(content));

            // a 16-octet session key in front of an AES-256 payload is inconsistent: the generic error, no plaintext
            byte[] shortKey = SecureRandom.GetNextBytes(Random, 16);
            byte[] mismatched = Arrays.Concatenate(
                Packet(PacketTag.PublicKeyEncryptedSession,
                    PkeskV6Body(pair.PublicKey, MLKem768X25519Fields(privateKey.GeneratePublicKey(), shortKey))),
                Packet(PacketTag.SymmetricEncryptedIntegrityProtected,
                    SeipdBody(SymmetricKeyAlgorithmTag.Aes256, AeadAlgorithmTag.Gcm, 0,
                        SecureRandom.GetNextBytes(Random, 32), SecureRandom.GetNextBytes(Random, SaltLength),
                        Packet(PacketTag.LiteralData, LiteralBody(content)))));
            var list = (PgpEncryptedDataList)new PgpObjectFactory(mismatched).NextPgpObject();
            var e = Assert.Throws<PgpException>(
                () => ((PgpPublicKeyEncryptedData)list[0]).GetDataStream(pair.PrivateKey));
            Assert.That(e.Message, Is.EqualTo("exception decrypting session key"));
        }

        private static byte[] EncryptWithLibrary(PgpEncryptedDataGenerator generator, byte[] content)
        {
            var message = new MemoryStream();
            using (Stream encrypted = generator.Open(message, new byte[512]))
            using (Stream literal = new PgpLiteralDataGenerator().Open(encrypted, PgpLiteralData.Binary, "",
                content.Length, DateTime.UtcNow))
            {
                literal.Write(content, 0, content.Length);
            }
            return message.ToArray();
        }

        private static byte[] DecryptWithLibrary(byte[] message, PgpPrivateKey privateKey)
        {
            var list = (PgpEncryptedDataList)new PgpObjectFactory(message).NextPgpObject();
            var encData = (PgpPublicKeyEncryptedData)list[0];
            Assert.That(encData.Version, Is.EqualTo(6));
            Stream decrypted = encData.GetDataStream(privateKey);
            var literal = (PgpLiteralData)new PgpObjectFactory(decrypted).NextPgpObject();
            byte[] content = Streams.ReadAll(literal.GetDataStream());
            Assert.That(encData.Verify(), Is.True);
            return content;
        }
    }
}
