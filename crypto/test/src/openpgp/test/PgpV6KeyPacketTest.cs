using System;
using System.IO;
using System.Linq;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    /// <summary>Tests for the key material packets of RFC 9580 version 6 keys and the RFC 9980 algorithms.</summary>
    [TestFixture]
    public class PgpV6KeyPacketTest
    {
        private static byte[] Sequence(int length)
        {
            byte[] result = new byte[length];
            for (int i = 0; i < length; ++i)
            {
                result[i] = (byte)(i * 13 + 5);
            }
            return result;
        }

        private static T FromStream<T>(Func<BcpgInputStream, T> create, byte[] data)
        {
            return create(BcpgInputStream.Wrap(new MemoryStream(data, false)));
        }

        [Test]
        public void CompositeKeyClassesSplitTheirComponents()
        {
            // ML-DSA-65+Ed25519
            byte[] pub = Sequence(MLDsa65Ed25519PublicBcpgKey.Length);
            Assert.That(MLDsa65Ed25519PublicBcpgKey.Length, Is.EqualTo(1984));
            var mldsa65Pub = new MLDsa65Ed25519PublicBcpgKey(pub);
            Assert.That(mldsa65Pub.GetEd25519PublicKey(), Is.EqualTo(Arrays.CopyOfRange(pub, 0, 32)));
            Assert.That(mldsa65Pub.GetMLDsaPublicKey(), Is.EqualTo(Arrays.CopyOfRange(pub, 32, 1984)));
            Assert.That(mldsa65Pub.GetMLDsaPublicKey().Length, Is.EqualTo(1952));

            byte[] sec = Sequence(MLDsa65Ed25519SecretBcpgKey.Length);
            Assert.That(MLDsa65Ed25519SecretBcpgKey.Length, Is.EqualTo(64));
            var mldsa65Sec = new MLDsa65Ed25519SecretBcpgKey(sec);
            Assert.That(mldsa65Sec.GetEd25519SecretKey(), Is.EqualTo(Arrays.CopyOfRange(sec, 0, 32)));
            Assert.That(mldsa65Sec.GetMLDsaSeed(), Is.EqualTo(Arrays.CopyOfRange(sec, 32, 64)));

            // ML-DSA-87+Ed448
            pub = Sequence(MLDsa87Ed448PublicBcpgKey.Length);
            Assert.That(MLDsa87Ed448PublicBcpgKey.Length, Is.EqualTo(2649));
            var mldsa87Pub = new MLDsa87Ed448PublicBcpgKey(pub);
            Assert.That(mldsa87Pub.GetEd448PublicKey(), Is.EqualTo(Arrays.CopyOfRange(pub, 0, 57)));
            Assert.That(mldsa87Pub.GetMLDsaPublicKey(), Is.EqualTo(Arrays.CopyOfRange(pub, 57, 2649)));
            Assert.That(mldsa87Pub.GetMLDsaPublicKey().Length, Is.EqualTo(2592));

            sec = Sequence(MLDsa87Ed448SecretBcpgKey.Length);
            Assert.That(MLDsa87Ed448SecretBcpgKey.Length, Is.EqualTo(89));
            var mldsa87Sec = new MLDsa87Ed448SecretBcpgKey(sec);
            Assert.That(mldsa87Sec.GetEd448SecretKey(), Is.EqualTo(Arrays.CopyOfRange(sec, 0, 57)));
            Assert.That(mldsa87Sec.GetMLDsaSeed(), Is.EqualTo(Arrays.CopyOfRange(sec, 57, 89)));

            // ML-KEM-1024+X448
            pub = Sequence(MLKem1024X448PublicBcpgKey.Length);
            Assert.That(MLKem1024X448PublicBcpgKey.Length, Is.EqualTo(1624));
            var mlkemPub = new MLKem1024X448PublicBcpgKey(pub);
            Assert.That(mlkemPub.GetX448PublicKey(), Is.EqualTo(Arrays.CopyOfRange(pub, 0, 56)));
            Assert.That(mlkemPub.GetMLKemPublicKey(), Is.EqualTo(Arrays.CopyOfRange(pub, 56, 1624)));
            Assert.That(mlkemPub.GetMLKemPublicKey().Length, Is.EqualTo(1568));

            sec = Sequence(MLKem1024X448SecretBcpgKey.Length);
            Assert.That(MLKem1024X448SecretBcpgKey.Length, Is.EqualTo(120));
            var mlkemSec = new MLKem1024X448SecretBcpgKey(sec);
            Assert.That(mlkemSec.GetX448SecretKey(), Is.EqualTo(Arrays.CopyOfRange(sec, 0, 56)));
            Assert.That(mlkemSec.GetMLKemSeed(), Is.EqualTo(Arrays.CopyOfRange(sec, 56, 120)));

            // the stream constructors read exactly the key material
            byte[] withTrailer = Arrays.Concatenate(Sequence(MLKem1024X448PublicBcpgKey.Length), new byte[]{ 0xAA });
            var bcpgIn = BcpgInputStream.Wrap(new MemoryStream(withTrailer, false));
            var fromStream = new MLKem1024X448PublicBcpgKey(bcpgIn);
            Assert.That(fromStream.GetKey(), Is.EqualTo(Sequence(MLKem1024X448PublicBcpgKey.Length)));
            Assert.That(bcpgIn.ReadByte(), Is.EqualTo(0xAA));
        }

        [Test]
        public void SlhDsaKeyClassesHaveParameterSetSpecificLengths()
        {
            Assert.That(SlhDsaPublicBcpgKey.GetKeyLength(PublicKeyAlgorithmTag.SlhDsa_Shake128s), Is.EqualTo(32));
            Assert.That(SlhDsaPublicBcpgKey.GetKeyLength(PublicKeyAlgorithmTag.SlhDsa_Shake128f), Is.EqualTo(32));
            Assert.That(SlhDsaPublicBcpgKey.GetKeyLength(PublicKeyAlgorithmTag.SlhDsa_Shake256s), Is.EqualTo(64));
            Assert.Throws<ArgumentException>(() => SlhDsaPublicBcpgKey.GetKeyLength(PublicKeyAlgorithmTag.Ed25519));

            foreach (var algorithm in new[]
            {
                PublicKeyAlgorithmTag.SlhDsa_Shake128s,
                PublicKeyAlgorithmTag.SlhDsa_Shake128f,
                PublicKeyAlgorithmTag.SlhDsa_Shake256s,
            })
            {
                int length = SlhDsaPublicBcpgKey.GetKeyLength(algorithm);
                Assert.That(new SlhDsaPublicBcpgKey(algorithm, Sequence(length)).GetKey().Length, Is.EqualTo(length));
                Assert.That(new SlhDsaSecretBcpgKey(algorithm, Sequence(2 * length)).GetKey().Length,
                    Is.EqualTo(2 * length));

                // the secret key contains the public key (PK.seed || PK.root) at the end
                Assert.Throws<ArgumentException>(() => new SlhDsaPublicBcpgKey(algorithm, Sequence(length + 1)));
                Assert.Throws<ArgumentException>(() => new SlhDsaPublicBcpgKey(algorithm, Sequence(length - 1)));
                Assert.Throws<ArgumentException>(() => new SlhDsaSecretBcpgKey(algorithm, Sequence(length)));
            }

            // the length depends on the parameter set
            Assert.Throws<ArgumentException>(() => new SlhDsaPublicBcpgKey(PublicKeyAlgorithmTag.SlhDsa_Shake256s,
                Sequence(32)));
            Assert.Throws<ArgumentException>(() => new SlhDsaPublicBcpgKey(PublicKeyAlgorithmTag.Ed25519,
                Sequence(32)));
        }

        [Test]
        public void WrongKeyLengthsAreRejected()
        {
            Assert.Throws<ArgumentException>(() => new MLDsa65Ed25519PublicBcpgKey(new byte[1983]));
            Assert.Throws<ArgumentException>(() => new MLDsa65Ed25519SecretBcpgKey(new byte[65]));
            Assert.Throws<ArgumentException>(() => new MLDsa87Ed448PublicBcpgKey(new byte[2648]));
            Assert.Throws<ArgumentException>(() => new MLDsa87Ed448SecretBcpgKey(new byte[88]));
            Assert.Throws<ArgumentException>(() => new MLKem1024X448PublicBcpgKey(new byte[1625]));
            Assert.Throws<ArgumentException>(() => new MLKem1024X448SecretBcpgKey(new byte[121]));
        }

        /// <summary>Body of a public key packet with the given version and algorithm.</summary>
        private static byte[] PublicKeyPacketBody(int version, PublicKeyAlgorithmTag algorithm, int declaredLength,
            int actualLength)
        {
            var body = new MemoryStream();
            body.WriteByte((byte)version);
            body.Write(new byte[]{ 0x63, 0x87, 0x7f, 0xe3 }, 0, 4);
            body.WriteByte((byte)algorithm);
            if (version == 6)
            {
                body.Write(new byte[]{ (byte)(declaredLength >> 24), (byte)(declaredLength >> 16),
                    (byte)(declaredLength >> 8), (byte)declaredLength }, 0, 4);
            }
            byte[] key = Sequence(actualLength);
            body.Write(key, 0, key.Length);
            return body.ToArray();
        }

        private static PublicKeyPacket ParsePublicKeyPacket(byte[] body, PacketTag tag = PacketTag.PublicKey) =>
            PgpV6TestUtilities.ReadPacket<PublicKeyPacket>(PgpV6TestUtilities.NewFormatPacket(tag, body));

        private static readonly object[][] Version6Keys =
        {
            new object[]{ PublicKeyAlgorithmTag.X25519, 32 },
            new object[]{ PublicKeyAlgorithmTag.X448, 56 },
            new object[]{ PublicKeyAlgorithmTag.Ed25519, 32 },
            new object[]{ PublicKeyAlgorithmTag.Ed448, 57 },
            new object[]{ PublicKeyAlgorithmTag.MLKem768_X25519, 1216 },
            new object[]{ PublicKeyAlgorithmTag.MLKem1024_X448, 1624 },
            new object[]{ PublicKeyAlgorithmTag.MLDsa65_Ed25519, 1984 },
            new object[]{ PublicKeyAlgorithmTag.MLDsa87_Ed448, 2649 },
            new object[]{ PublicKeyAlgorithmTag.SlhDsa_Shake128s, 32 },
            new object[]{ PublicKeyAlgorithmTag.SlhDsa_Shake128f, 32 },
            new object[]{ PublicKeyAlgorithmTag.SlhDsa_Shake256s, 64 },
        };

        [TestCaseSource(nameof(Version6Keys))]
        public void Version6KeyLengthMustMatchAlgorithm(PublicKeyAlgorithmTag algorithm, int length)
        {
            var packet = ParsePublicKeyPacket(PublicKeyPacketBody(6, algorithm, length, length));
            Assert.That(packet.Algorithm, Is.EqualTo(algorithm));
            Assert.That(packet.Key, Is.Not.InstanceOf<UnknownBcpgKey>());
            Assert.That(((OctetArrayBcpgKey)packet.Key).GetKey().Length, Is.EqualTo(length));

            // the key material length field disagrees with the algorithm
            Assert.Throws<MalformedPacketException>(
                () => ParsePublicKeyPacket(PublicKeyPacketBody(6, algorithm, length + 1, length + 1)));
            Assert.Throws<MalformedPacketException>(
                () => ParsePublicKeyPacket(PublicKeyPacketBody(6, algorithm, length - 1, length - 1)));
        }

        private static readonly PublicKeyAlgorithmTag[] Version6OnlyAlgorithms =
        {
            PublicKeyAlgorithmTag.MLKem1024_X448,
            PublicKeyAlgorithmTag.MLDsa65_Ed25519,
            PublicKeyAlgorithmTag.MLDsa87_Ed448,
            PublicKeyAlgorithmTag.SlhDsa_Shake128s,
            PublicKeyAlgorithmTag.SlhDsa_Shake128f,
            PublicKeyAlgorithmTag.SlhDsa_Shake256s,
        };

        [TestCaseSource(nameof(Version6OnlyAlgorithms))]
        public void Version6OnlyAlgorithmsAreOpaqueInVersion4Keys(PublicKeyAlgorithmTag algorithm)
        {
            // as a public key packet, the key material is the rest of the packet
            var packet = ParsePublicKeyPacket(PublicKeyPacketBody(4, algorithm, 0, 50));
            Assert.That(packet.Key, Is.InstanceOf<UnknownBcpgKey>());
            Assert.That(((UnknownBcpgKey)packet.Key).GetKey().Length, Is.EqualTo(50));

            var subkeyPacket = ParsePublicKeyPacket(PublicKeyPacketBody(4, algorithm, 0, 50), PacketTag.PublicSubkey);
            Assert.That(subkeyPacket.Key, Is.InstanceOf<UnknownBcpgKey>());

            // the key can be used in a key ring, but it cannot be turned into a key
            var key = new PgpPublicKey(packet);
            Assert.That(key.Algorithm, Is.EqualTo(algorithm));
            Assert.That(key.GetFingerprint().Length, Is.EqualTo(20));
            Assert.Throws<PgpException>(() => key.GetKey());

            // inside a secret key packet, the extent of the key material is not known
            byte[] secretBody = Arrays.Concatenate(PublicKeyPacketBody(4, algorithm, 0, 50), new byte[]{ 0, 1, 2 });
            Assert.Throws<MalformedPacketException>(() => PgpV6TestUtilities.ReadPacket<SecretKeyPacket>(
                PgpV6TestUtilities.NewFormatPacket(PacketTag.SecretKey, secretBody)));
            Assert.Throws<MalformedPacketException>(() => PgpV6TestUtilities.ReadPacket<SecretSubkeyPacket>(
                PgpV6TestUtilities.NewFormatPacket(PacketTag.SecretSubkey, secretBody)));
        }

        [TestCase("a1", "c789e17d9dbdca7b3c833a3c063feb0353f80ad911fe27868fb0645df803e947",
            "dafe0eebb2675ecfcdc20a23fe89ca5d12e83f527dfa354b6dcf662131a48b9d")]
        [TestCase("a3", "a3e2e14b6a493ff930fb27321f125e9a6880338be9fb7da3ae065ea65793242f",
            "7dae8fbce23022607167af72a002e774e0ca379a2d7ae072384e1e8fde3265e4")]
        [TestCase("a4", "0d7a8be1410cd68eed4845ab487b4b4cfaecd8ebad1a1166a84230499200ee20",
            "65090e147a8116ab7f62ab4ec7aae59d9e6532feb2af230c73cdc869fbc60c8f")]
        [TestCase("a5", "eed4d13fc36c78e48276a93233339c4dd230fd5f6f5c5b82c63d5c0b5e361d92",
            "3e8745a4bb488779e0f32480fa23f8d0bfd8c2f49d7f74e957e1c2ffc2ef4bfc")]
        [TestCase("a6", "d54e0307021169f7b88beb2b76e3aad0e114be1a8f982d74dba9ca51d03537f4",
            "d8875664256c382dd7f3a5ce05021088922811f5d0b1a1f8c7769944a51b7002")]
        [TestCase("a7", "72fff84863aeba67f0d1d7691173247dd427533b9d7ee76011c6f77f2ce9fa7a",
            "570a5bbab93169876a8240da35a1ada7ba8a640aabe3ab467c797214844df15f")]
        public void Rfc9980KeyFingerprintsAndIds(string vector, string primaryFingerprint, string subkeyFingerprint)
        {
            var publicRing = new PgpPublicKeyRing(PgpV6TestUtilities.LoadRfc9980(vector + "-public-key.asc"));
            var secretRing = new PgpSecretKeyRing(PgpV6TestUtilities.LoadRfc9980(vector + "-secret-key.asc"));

            foreach (PgpPublicKey[] keys in new[]
            {
                publicRing.GetPublicKeys().ToArray(),
                secretRing.GetPublicKeys().ToArray(),
            })
            {
                Assert.That(keys.Length, Is.EqualTo(2));

                Assert.That(keys[0].Version, Is.EqualTo(6));
                Assert.That(Hex.ToHexString(keys[0].GetFingerprint()), Is.EqualTo(primaryFingerprint));
                Assert.That(keys[0].KeyId, Is.EqualTo(unchecked((long)Convert.ToUInt64(
                    primaryFingerprint.Substring(0, 16), 16))));

                Assert.That(keys[1].Version, Is.EqualTo(6));
                Assert.That(Hex.ToHexString(keys[1].GetFingerprint()), Is.EqualTo(subkeyFingerprint));
                Assert.That(keys[1].KeyId, Is.EqualTo(unchecked((long)Convert.ToUInt64(
                    subkeyFingerprint.Substring(0, 16), 16))));
            }

            // the ring re-encodes exactly
            Assert.That(Arrays.AreEqual(PgpV6TestUtilities.LoadRfc9980(vector + "-public-key.asc"),
                publicRing.GetEncoded()), Is.True);
            Assert.That(Arrays.AreEqual(PgpV6TestUtilities.LoadRfc9980(vector + "-secret-key.asc"),
                secretRing.GetEncoded()), Is.True);
        }

        // the size of the curve, of the curve of a composite key, or of an SLH-DSA public key
        [TestCase("a1", 256, 256)]
        [TestCase("a3", 256, 256)]
        [TestCase("a4", 448, 448)]
        [TestCase("a5", 256, 256)]
        [TestCase("a6", 256, 256)]
        [TestCase("a7", 512, 448)]
        public void Rfc9980KeyStrengths(string vector, int primaryStrength, int subkeyStrength)
        {
            PgpPublicKey[] keys = new PgpPublicKeyRing(PgpV6TestUtilities.LoadRfc9980(vector + "-public-key.asc"))
                .GetPublicKeys().ToArray();

            Assert.That(keys[0].BitStrength, Is.EqualTo(primaryStrength));
            Assert.That(keys[1].BitStrength, Is.EqualTo(subkeyStrength));
        }

        [Test]
        public void Rfc9580KeyStrengths()
        {
            PgpPublicKey[] keys = new PgpPublicKeyRing(PgpV6TestUtilities.LoadRfc9580("a3-v6-certificate.asc"))
                .GetPublicKeys().ToArray();
            Assert.That(keys[0].Algorithm, Is.EqualTo(PublicKeyAlgorithmTag.Ed25519));
            Assert.That(keys[0].BitStrength, Is.EqualTo(256));
            Assert.That(keys[1].Algorithm, Is.EqualTo(PublicKeyAlgorithmTag.X25519));
            Assert.That(keys[1].BitStrength, Is.EqualTo(256));

            var random = new SecureRandom();
            var ed448 = new Ed448PrivateKeyParameters(random);
            var x448 = new X448PrivateKeyParameters(random);
            Assert.That(new PgpPublicKey(6, PublicKeyAlgorithmTag.Ed448, ed448.GeneratePublicKey(), DateTime.UtcNow)
                .BitStrength, Is.EqualTo(448));
            Assert.That(new PgpPublicKey(6, PublicKeyAlgorithmTag.X448, x448.GeneratePublicKey(), DateTime.UtcNow)
                .BitStrength, Is.EqualTo(448));
        }

        [Test]
        public void Rfc9580CertificateFingerprintsAndIds()
        {
            byte[] encoding = PgpV6TestUtilities.LoadRfc9580("a3-v6-certificate.asc");
            var ring = new PgpPublicKeyRing(encoding);
            var keys = ring.GetPublicKeys().ToArray();

            Assert.That(Hex.ToHexString(keys[0].GetFingerprint()),
                Is.EqualTo("cb186c4f0609a697e4d52dfa6c722b0c1f1e27c18a56708f6525ec27bad9acc9"));
            Assert.That(Hex.ToHexString(keys[1].GetFingerprint()),
                Is.EqualTo("12c83f1e706f6308fe151a417743a1f033790e93e9978488d1db378da9930885"));
            Assert.That(keys[1].KeyId, Is.EqualTo(unchecked((long)0x12c83f1e706f6308UL)));
            Assert.That(Arrays.AreEqual(encoding, ring.GetEncoded()), Is.True);
        }
    }
}
