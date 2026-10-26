using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    /// <summary>
    /// Robustness tests for the RFC 9980 ML-KEM-768+X25519 support: systematic mutation of messages and keys,
    /// malformed inputs, real Ed25519/Ed448 signatures with weak and strong hashes, and concurrent use.
    /// </summary>
    /// <remarks>
    /// The invariant checked throughout: processing hostile input only ever fails with <see cref="PgpException"/> or
    /// <see cref="IOException"/>, and never yields plaintext other than the original with a passing integrity check.
    /// </remarks>
    [TestFixture]
    public class PgpMLKemX25519RobustnessTest
    {
        private static readonly SecureRandom Random = new SecureRandom();

        private static readonly byte[] Content = Encoding.UTF8.GetBytes("robustness test content");

        private PgpSecretKeyRing m_secretRing;
        private PgpPublicKeyRing m_publicRing;
        private PgpPrivateKey m_privateKey;

        [OneTimeSetUp]
        public void SetUp()
        {
            m_secretRing = PgpMLKemX25519Test.GenerateRing("robustness", null, out m_publicRing);
            m_privateKey = PgpMLKemX25519Test.MLKemSubkey(m_secretRing).ExtractPrivateKey(new char[0]);
        }

        private byte[] EncryptContent() =>
            PgpMLKemX25519Test.Encrypt(new[]{ PgpMLKemX25519Test.MLKemSubkey(m_publicRing) }, Content);

        private enum Outcome { Rejected, Original }

        /// <summary>
        /// Try to decrypt a (possibly hostile) message with the first PKESK. Fails the test if anything other than a
        /// clean rejection or the original, integrity-checked plaintext comes out.
        /// </summary>
        private static Outcome TryDecrypt(byte[] message, PgpPrivateKey privateKey, string context)
        {
            try
            {
                var factory = new PgpObjectFactory(message);
                if (!(factory.NextPgpObject() is PgpEncryptedDataList encList) || encList.IsEmpty)
                    return Outcome.Rejected;

                var encData = encList[0] as PgpPublicKeyEncryptedData;
                if (encData == null)
                    return Outcome.Rejected;

                var result = PgpMLKemX25519Test.ReadContent(encData, encData.GetDataStream(privateKey), null,
                    SymmetricKeyAlgorithmTag.Null);
                if (!result.IntegrityVerified)
                    return Outcome.Rejected;

                Assert.That(Arrays.AreEqual(Content, result.Content), Is.True,
                    context + ": integrity check passed with different plaintext");
                return Outcome.Original;
            }
            catch (PgpException)
            {
                return Outcome.Rejected;
            }
            catch (IOException)
            {
                return Outcome.Rejected;
            }
            catch (UnsupportedPacketVersionException)
            {
                // Parse error for garbage plaintext (e.g. a corrupted payload), reported before the integrity check
                return Outcome.Rejected;
            }
            catch (InvalidDataException)
            {
                // Garbage plaintext that looks like compressed data (System.IO.Compression), also before the
                // integrity check
                return Outcome.Rejected;
            }
            catch (Exception e)
            {
                Assert.Fail(context + ": unexpected " + e.GetType().Name + ": " + e.Message);
                throw;
            }
        }

        [Test]
        public void EveryPkeskByteMutation()
        {
            byte[][] packets = PgpUnsupportedVersionTest.SplitPackets(EncryptContent());
            byte[] pkesk = packets[0];
            int body = PgpMLKemX25519Test.HeaderLength(pkesk);
            const int keyIdStart = 1, keyIdEnd = 9;

            int rejected = 0;
            foreach (byte mask in new byte[]{ 0x01, 0x80 })
            {
                for (int offset = body; offset < pkesk.Length; ++offset)
                {
                    byte[] mutated = Arrays.Clone(pkesk);
                    mutated[offset] ^= mask;
                    Outcome outcome = TryDecrypt(Arrays.Concatenate(mutated, packets[1]), m_privateKey,
                        $"PKESK offset {offset - body} mask {mask:x2}");

                    int field = offset - body;
                    bool isKeyId = field >= keyIdStart && field < keyIdEnd;
                    if (isKeyId)
                    {
                        // The key ID is not authenticated; decryption with the right key still works
                        Assert.That(outcome, Is.EqualTo(Outcome.Original), "key ID offset " + field);
                    }
                    else
                    {
                        Assert.That(outcome, Is.EqualTo(Outcome.Rejected), "PKESK offset " + field);
                        ++rejected;
                    }
                }
            }
            Assert.That(rejected, Is.EqualTo(2 * (pkesk.Length - body - 8)));
        }

        [Test]
        public void EveryAlgorithmOctet()
        {
            byte[][] packets = PgpUnsupportedVersionTest.SplitPackets(EncryptContent());
            int algPos = PgpMLKemX25519Test.HeaderLength(packets[0]) + 9;

            for (int alg = 0; alg < 256; ++alg)
            {
                if (alg == (int)PublicKeyAlgorithmTag.MLKem768_X25519)
                    continue;

                byte[] mutated = Arrays.Clone(packets[0]);
                mutated[algPos] = (byte)alg;
                Assert.That(TryDecrypt(Arrays.Concatenate(mutated, packets[1]), m_privateKey, "algorithm " + alg),
                    Is.EqualTo(Outcome.Rejected), "algorithm " + alg);
            }
        }

        [Test]
        public void TruncatedMessages()
        {
            byte[] message = EncryptContent();
            for (int length = 0; length < message.Length; length += (length < 1300 ? 1 : 7))
            {
                TryDecrypt(Arrays.CopyOfRange(message, 0, length), m_privateKey, "truncated to " + length);
            }
        }

        [Test]
        public void RandomPayloadCorruption()
        {
            byte[][] packets = PgpUnsupportedVersionTest.SplitPackets(EncryptContent());
            byte[] seipd = packets[1];
            int body = PgpMLKemX25519Test.HeaderLength(seipd);

            for (int i = 0; i < 500; ++i)
            {
                byte[] mutated = Arrays.Clone(seipd);
                int offset = body + Random.Next(seipd.Length - body);
                mutated[offset] ^= (byte)(1 + Random.Next(255));
                Assert.That(TryDecrypt(Arrays.Concatenate(packets[0], mutated), m_privateKey, "SEIPD " + offset),
                    Is.EqualTo(Outcome.Rejected), "SEIPD offset " + offset);
            }
        }

        [Test]
        public void EverySecretKeyByteMutation()
        {
            byte[] encoded = m_secretRing.GetEncoded();
            var subkey = (MLKem768X25519PublicBcpgKey)PgpMLKemX25519Test.MLKemSubkey(m_publicRing).PublicKeyPacket.Key;
            int secretPos = IndexOf(encoded, subkey.GetKey()) + MLKem768X25519PublicBcpgKey.Length + 1;
            Assert.That(secretPos, Is.GreaterThan(MLKem768X25519PublicBcpgKey.Length));

            byte[] message = EncryptContent();
            int accepted = 0;
            for (int i = 0; i < MLKem768X25519SecretBcpgKey.Length; ++i)
            {
                foreach (byte mask in new byte[]{ 0x01, 0x40, 0x80 })
                {
                    byte[] mutated = Arrays.Clone(encoded);
                    mutated[secretPos + i] ^= mask;
                    PgpSecretKey secretKey = PgpMLKemX25519Test.MLKemSubkey(new PgpSecretKeyRing(mutated));

                    PgpPrivateKey privateKey;
                    try
                    {
                        privateKey = secretKey.ExtractPrivateKey(new char[0]);
                    }
                    catch (PgpException)
                    {
                        continue;
                    }

                    // Changes the public key does not depend on cannot be detected: X25519 bits that clamping
                    // ignores, and the ML-KEM implicit-rejection value z (seed bytes 32-63, secret bytes 64-95). Such
                    // a key is equivalent for valid ciphertexts and must still decrypt.
                    bool clampedBit = (i == 0 && (mask & 0x07) != 0) || (i == 31 && (mask & 0xC0) != 0);
                    bool zByte = i >= 64;
                    Assert.That(clampedBit || zByte, Is.True, $"secret byte {i} mask {mask:x2} was not detected");
                    Assert.That(TryDecrypt(message, privateKey, "equivalent key"), Is.EqualTo(Outcome.Original));
                    ++accepted;
                }
            }
            Assert.That(accepted, Is.LessThanOrEqualTo(3 + 32 * 3));
        }

        [Test]
        public void LowOrderEcdhCipherText()
        {
            byte[][] packets = PgpUnsupportedVersionTest.SplitPackets(EncryptContent());
            int ecdhPos = PgpMLKemX25519Test.HeaderLength(packets[0]) + 10;

            var lowOrderPoints = new[]{
                new byte[32],
                Hex.Decode("0100000000000000000000000000000000000000000000000000000000000000"),
                Hex.Decode("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
                Hex.Decode("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
                Hex.Decode("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
            };
            foreach (byte[] point in lowOrderPoints)
            {
                byte[] mutated = Arrays.Clone(packets[0]);
                Array.Copy(point, 0, mutated, ecdhPos, 32);
                Assert.That(TryDecrypt(Arrays.Concatenate(mutated, packets[1]), m_privateKey, Hex.ToHexString(point)),
                    Is.EqualTo(Outcome.Rejected));
            }

            // The all-zero shared secret itself is rejected by the KEM, not only by the key unwrap
            var privateParams = (MLKem768X25519PrivateKeyParameters)m_privateKey.Key;
            Assert.Throws<InvalidOperationException>(() => PgpMLKemX25519.Decapsulate(privateParams, new byte[32],
                new byte[32], new byte[PgpMLKemX25519.MLKemCipherTextLength]));
        }

        [Test]
        public void SessionKeyForAnotherKeyRejected()
        {
            PgpSecretKeyRing otherRing = PgpMLKemX25519Test.GenerateRing("other", null, out _);
            PgpPrivateKey otherKey = PgpMLKemX25519Test.MLKemSubkey(otherRing).ExtractPrivateKey(new char[0]);

            Assert.That(TryDecrypt(EncryptContent(), otherKey, "other key"), Is.EqualTo(Outcome.Rejected));
        }

        [Test]
        public void MalformedKeyMaterial()
        {
            // ML-KEM encapsulation key with coefficients >= q fails the FIPS 203 modulus check
            byte[] material = new byte[MLKem768X25519PublicBcpgKey.Length];
            Arrays.Fill(material, 0xFF);
            var packet = new PublicSubkeyPacket(PublicKeyPacket.Version4, PublicKeyAlgorithmTag.MLKem768_X25519,
                DateTime.UtcNow, new MLKem768X25519PublicBcpgKey(material));
            var badKey = new PgpPublicKey(packet);

            Assert.That(badKey.IsEncryptionKey, Is.True);
            Assert.Throws<PgpException>(() => badKey.GetKey());

            var encGen = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, true, Random);
            encGen.AddMethod(badKey);
            Assert.Throws<PgpException>(() => encGen.Open(new MemoryStream(), new byte[1024]));

            // Truncated key material
            byte[] encoded = new PublicSubkeyPacket(PublicKeyPacket.Version4, PublicKeyAlgorithmTag.MLKem768_X25519,
                DateTime.UtcNow, new MLKem768X25519PublicBcpgKey(new byte[1216])).GetEncoded(PacketFormat.Current);
            int bodyLength = encoded.Length - 3 - 100;
            encoded[1] = (byte)(((bodyLength - 192) >> 8) + 192);
            encoded[2] = (byte)(bodyLength - 192);
            byte[] truncated = Arrays.CopyOfRange(encoded, 0, 3 + bodyLength);
            Assert.Throws<EndOfStreamException>(
                () => BcpgInputStream.Wrap(new MemoryStream(truncated, false)).ReadPacket());
        }

        [Test]
        public void ConcurrentUseOfSharedKeys()
        {
            PgpPublicKey recipient = PgpMLKemX25519Test.MLKemSubkey(m_publicRing);
            var failures = new System.Collections.Concurrent.ConcurrentBag<string>();

            Parallel.For(0, 64, i =>
            {
                try
                {
                    byte[] content = Encoding.UTF8.GetBytes("message " + i);
                    byte[] message = PgpMLKemX25519Test.Encrypt(new[]{ recipient }, content);
                    var result = PgpMLKemX25519Test.Decrypt(message, m_privateKey);
                    if (!Arrays.AreEqual(content, result.Content) || !result.IntegrityVerified)
                    {
                        failures.Add("wrong result in iteration " + i);
                    }
                }
                catch (Exception e)
                {
                    failures.Add(i + ": " + e);
                }
            });

            Assert.That(failures, Is.Empty);
        }

        /// <summary>
        /// Build a v4 binary-document signature with a native Ed25519/Ed448 key (RFC 9580 algorithms 27/28) by hand,
        /// so that hash algorithms that BC would never choose itself can be tested.
        /// </summary>
        private static byte[] BuildEdDsaSignature(PublicKeyAlgorithmTag algorithm, HashAlgorithmTag hashAlgorithm,
            AsymmetricKeyParameterPair keys, byte[] data)
        {
            // hashed area: signature creation time subpacket
            uint time = (uint)(DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
            byte[] hashed = { 5, 2, (byte)(time >> 24), (byte)(time >> 16), (byte)(time >> 8), (byte)time };
            byte[] hashedPart = Arrays.Concatenate(
                new byte[]{ 4, 0x00, (byte)algorithm, (byte)hashAlgorithm, 0, (byte)hashed.Length }, hashed);
            byte[] trailer = { 0x04, 0xFF, 0, 0, 0, (byte)hashedPart.Length };

            var digest = PgpUtilities.CreateDigest(hashAlgorithm);
            digest.BlockUpdate(data, 0, data.Length);
            digest.BlockUpdate(hashedPart, 0, hashedPart.Length);
            digest.BlockUpdate(trailer, 0, trailer.Length);
            byte[] hash = DigestUtilities.DoFinal(digest);

            var signer = keys.CreateSigner();
            signer.Init(true, keys.Private);
            signer.BlockUpdate(hash, 0, hash.Length);
            byte[] signature = signer.GenerateSignature();

            byte[] body = Arrays.ConcatenateAll(hashedPart, new byte[]{ 0, 0, hash[0], hash[1] }, signature);
            return PgpUnsupportedVersionTest.NewFormatPacket(PacketTag.Signature, body);
        }

        private sealed class AsymmetricKeyParameterPair
        {
            internal Org.BouncyCastle.Crypto.AsymmetricKeyParameter Private;
            internal PgpPublicKey Public;
            internal Func<Org.BouncyCastle.Crypto.ISigner> CreateSigner;
        }

        private static AsymmetricKeyParameterPair NewEdKey(PublicKeyAlgorithmTag algorithm)
        {
            if (algorithm == PublicKeyAlgorithmTag.Ed25519)
            {
                var privateKey = new Ed25519PrivateKeyParameters(Random);
                var packet = new PublicKeyPacket(PublicKeyPacket.Version4, algorithm, DateTime.UtcNow,
                    new Ed25519PublicBcpgKey(privateKey.GeneratePublicKey().GetEncoded()));
                return new AsymmetricKeyParameterPair{ Private = privateKey, Public = new PgpPublicKey(packet),
                    CreateSigner = () => new Ed25519Signer() };
            }
            else
            {
                var privateKey = new Ed448PrivateKeyParameters(Random);
                var packet = new PublicKeyPacket(PublicKeyPacket.Version4, algorithm, DateTime.UtcNow,
                    new Ed448PublicBcpgKey(privateKey.GeneratePublicKey().GetEncoded()));
                return new AsymmetricKeyParameterPair{ Private = privateKey, Public = new PgpPublicKey(packet),
                    CreateSigner = () => new Ed448Signer(Arrays.EmptyBytes) };
            }
        }

        private static bool VerifyDirect(byte[] signaturePacket, PgpPublicKey key, byte[] data)
        {
            var sigList = (PgpSignatureList)new PgpObjectFactory(signaturePacket).NextPgpObject();
            PgpSignature signature = sigList[0];
            signature.InitVerify(key);
            signature.Update(data);
            return signature.Verify();
        }

        private static bool VerifyOnePass(PublicKeyAlgorithmTag algorithm, HashAlgorithmTag hashAlgorithm,
            byte[] signaturePacket, PgpPublicKey key, byte[] data)
        {
            byte[] ops = PgpUnsupportedVersionTest.NewFormatPacket(PacketTag.OnePassSignature,
                Arrays.Concatenate(new byte[]{ 3, 0x00, (byte)hashAlgorithm, (byte)algorithm }, new byte[]{ 0, 0, 0, 0,
                    0, 0, 0, 0, 1 }));
            byte[] literal = PgpUnsupportedVersionTest.NewFormatPacket(PacketTag.LiteralData,
                Arrays.Concatenate(new byte[]{ (byte)'b', 0, 0, 0, 0, 0 }, data));
            var factory = new PgpObjectFactory(Arrays.ConcatenateAll(ops, literal, signaturePacket));

            PgpOnePassSignature onePass = ((PgpOnePassSignatureList)factory.NextPgpObject())[0];
            onePass.InitVerify(key);
            onePass.Update(Streams.ReadAll(((PgpLiteralData)factory.NextPgpObject()).GetDataStream()));
            return onePass.Verify(((PgpSignatureList)factory.NextPgpObject())[0]);
        }

        [TestCase(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha256, true)]
        [TestCase(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha512, true)]
        [TestCase(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha3_256, true)]
        [TestCase(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha1, false)]
        [TestCase(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha224, false)]
        [TestCase(PublicKeyAlgorithmTag.Ed448, HashAlgorithmTag.Sha512, true)]
        [TestCase(PublicKeyAlgorithmTag.Ed448, HashAlgorithmTag.Sha3_512, true)]
        [TestCase(PublicKeyAlgorithmTag.Ed448, HashAlgorithmTag.Sha256, false)]
        [TestCase(PublicKeyAlgorithmTag.Ed448, HashAlgorithmTag.Sha384, false)]
        public void EdDsaSignatureHashRules(PublicKeyAlgorithmTag algorithm, HashAlgorithmTag hashAlgorithm,
            bool expected)
        {
            AsymmetricKeyParameterPair keys = NewEdKey(algorithm);
            byte[] data = Encoding.UTF8.GetBytes("signed data");
            byte[] signature = BuildEdDsaSignature(algorithm, hashAlgorithm, keys, data);

            Assert.That(VerifyDirect(signature, keys.Public, data), Is.EqualTo(expected));
            Assert.That(VerifyOnePass(algorithm, hashAlgorithm, signature, keys.Public, data), Is.EqualTo(expected));

            if (expected)
            {
                // A valid signature must not verify for other data or another key
                Assert.That(VerifyDirect(signature, keys.Public, Encoding.UTF8.GetBytes("other data")), Is.False);
                Assert.That(VerifyDirect(signature, NewEdKey(algorithm).Public, data), Is.False);
            }
        }

        [Test]
        public void TruncatedEdDsaSignatureRejected()
        {
            AsymmetricKeyParameterPair keys = NewEdKey(PublicKeyAlgorithmTag.Ed25519);
            byte[] signature = BuildEdDsaSignature(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha256, keys,
                new byte[1]);
            byte[] body = Arrays.CopyOfRange(signature, 2, signature.Length - 1);

            // RFC 9580 5.2.5: the malformed signature is ignored, and processing goes on
            byte[] truncated = PgpUnsupportedVersionTest.NewFormatPacket(PacketTag.Signature, body);
            var signatures = (PgpSignatureList)new PgpObjectFactory(truncated).NextPgpObject();
            Assert.That(signatures.Count, Is.EqualTo(0));
        }

        private static int IndexOf(byte[] data, byte[] pattern)
        {
            for (int i = 0; i + pattern.Length <= data.Length; ++i)
            {
                if (Arrays.AreEqual(pattern, 0, pattern.Length, data, i, i + pattern.Length))
                    return i;
            }
            return -1;
        }
    }
}
