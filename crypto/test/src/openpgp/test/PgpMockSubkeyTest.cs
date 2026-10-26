using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    /// <summary>
    /// Certificates with "mock" subkeys: keys of an unknown algorithm, or of a known elliptic curve algorithm on an
    /// unknown curve, whose key material is either MPI-encoded or opaque. This is how future algorithms appear to
    /// today's implementations (the OpenPGP interoperability test suite's "Mock PQ subkey" test). Such a subkey must
    /// not make the certificate unusable: the primary key still verifies signatures, the other subkeys still work,
    /// the encoding round-trips byte for byte (so fingerprints are stable), and only the mock key itself is unusable.
    /// </summary>
    [TestFixture]
    public class PgpMockSubkeyTest
    {
        private static readonly SecureRandom Random = new SecureRandom();

        /// <summary>An OID under a private arc that no implementation knows as a curve.</summary>
        private static readonly DerObjectIdentifier UnknownCurve = new DerObjectIdentifier("1.3.6.1.4.1.44444.1.2.3");

        private static readonly byte[] Message = Strings.ToUtf8ByteArray("Hello World :)");

        public enum Encoding { Mpi, OpaqueSmall, OpaqueBig }

        private static byte[] MockKeyMaterial(PublicKeyAlgorithmTag algorithm, Encoding encoding)
        {
            var material = new MemoryStream();
            if (algorithm != (PublicKeyAlgorithmTag)99)
            {
                byte[] oid = UnknownCurve.GetEncoded();
                material.WriteByte((byte)(oid.Length - 2));
                material.Write(oid, 2, oid.Length - 2);
            }

            switch (encoding)
            {
            case Encoding.Mpi:
            {
                // a 263-bit point (0x40 prefix + 32 octets) as an MPI, and the KDF parameters for ECDH
                byte[] point = Arrays.Prepend(SecureRandom.GetNextBytes(Random, 32), 0x40);
                material.WriteByte(0x01);
                material.WriteByte(0x07);
                material.Write(point, 0, point.Length);
                if (algorithm == PublicKeyAlgorithmTag.ECDH)
                {
                    material.Write(
                        new byte[]{ 3, 1, (byte)HashAlgorithmTag.Sha256, (byte)SymmetricKeyAlgorithmTag.Aes128 },
                        0, 4);
                }
                break;
            }
            case Encoding.OpaqueSmall:
                material.Write(new byte[]{ 0xFF, 0xFE, 0xFD, 0x00, 0x01 }, 0, 5);
                break;
            default:
                // bigger than any MPI length prefix would suggest, with an MPI-like header that lies
                byte[] big = SecureRandom.GetNextBytes(Random, 3000);
                big[0] = 0xFF;
                big[1] = 0xFF;
                material.Write(big, 0, big.Length);
                break;
            }
            return material.ToArray();
        }

        private static PgpKeyPair Primary(int version)
        {
            var generator = new Ed25519KeyPairGenerator();
            generator.Init(new Ed25519KeyGenerationParameters(Random));
            return new PgpKeyPair(version,
                version == 6 ? PublicKeyAlgorithmTag.Ed25519 : PublicKeyAlgorithmTag.EdDsa_Legacy,
                generator.GenerateKeyPair(), DateTime.UtcNow.AddMinutes(-1));
        }

        private static PgpSignature Sign(PgpKeyPair signer, int type, Func<PgpSignatureGenerator, PgpSignature> make)
        {
            var generator = new PgpSignatureGenerator(signer.PublicKey.Algorithm, HashAlgorithmTag.Sha256);
            generator.InitSign(type, signer.PrivateKey, Random);
            return make(generator);
        }

        /// <summary>
        /// A certificate: primary key (with a direct-key signature for version 6), user ID, an X25519 encryption
        /// subkey, then the mock subkey (each with a valid binding signature).
        /// </summary>
        private static byte[] Certificate(PgpKeyPair primary, PublicKeyAlgorithmTag mockAlgorithm, byte[] material,
            out PgpKeyPair encryptionSubkey)
        {
            int version = primary.PublicKey.Version;
            const string userId = "Mock <mock@example.org>";
            PgpSignature certification = Sign(primary, PgpSignature.PositiveCertification,
                g => g.GenerateCertification(userId, primary.PublicKey));
            PgpPublicKey primaryKey = PgpPublicKey.AddCertification(primary.PublicKey, userId, certification);
            if (version == 6)
            {
                // RFC 9580 5.2.3.10: version 6 keys need a direct-key signature
                primaryKey = PgpPublicKey.AddCertification(primaryKey, Sign(primary, PgpSignature.DirectKey,
                    g => g.GenerateCertification(primary.PublicKey)));
            }

            encryptionSubkey = new PgpKeyPair(version, PublicKeyAlgorithmTag.X25519,
                PgpV6KeyGenerationTest.GenerateX(PublicKeyAlgorithmTag.X25519), DateTime.UtcNow.AddMinutes(-1));
            var mockPacket = new PublicSubkeyPacket((byte)version, mockAlgorithm, DateTime.UtcNow.AddMinutes(-1),
                new UnknownBcpgKey(material.Length, material));
            var mockKey = new PgpPublicKey(mockPacket);
            var encryptionKey = new PgpPublicKey(new PublicSubkeyPacket((byte)version, PublicKeyAlgorithmTag.X25519,
                encryptionSubkey.PublicKey.CreationTime, encryptionSubkey.PublicKey.PublicKeyPacket.Key));

            var output = new MemoryStream();
            primaryKey.Encode(output);
            foreach (PgpPublicKey subkey in new[]{ encryptionKey, mockKey })
            {
                PgpSignature binding = Sign(primary, PgpSignature.SubkeyBinding,
                    g => g.GenerateCertification(primaryKey, subkey));
                PgpPublicKey.AddCertification(subkey, binding).Encode(output);
            }
            return output.ToArray();
        }

        private static IEnumerable<TestCaseData> Cases()
        {
            foreach (int version in new[]{ 4, 6 })
            {
                foreach (var algorithm in new[]{ PublicKeyAlgorithmTag.ECDH, PublicKeyAlgorithmTag.ECDsa,
                    PublicKeyAlgorithmTag.EdDsa_Legacy, (PublicKeyAlgorithmTag)99 })
                {
                    foreach (Encoding encoding in Enum.GetValues(typeof(Encoding)))
                    {
                        yield return new TestCaseData(version, algorithm, encoding)
                            .SetName($"{{m}}(v{version},{algorithm},{encoding})");
                    }
                }
            }
        }

        [TestCaseSource(nameof(Cases))]
        public void CertificateWithMockSubkeyStaysUsable(int version, PublicKeyAlgorithmTag algorithm,
            Encoding encoding)
        {
            PgpKeyPair primary = Primary(version);
            byte[] material = MockKeyMaterial(algorithm, encoding);
            byte[] certificate = Certificate(primary, algorithm, material, out PgpKeyPair encryptionSubkey);

            var ring = new PgpPublicKeyRing(certificate);
            Assert.That(ring.GetPublicKeys().Count(), Is.EqualTo(3));
            Assert.That(ring.GetEncoded(), Is.EqualTo(certificate), "encoding round trip");

            PgpPublicKey mock = ring.GetPublicKeys().Last();
            Assert.That(mock.Algorithm, Is.EqualTo(algorithm));
            Assert.That(mock.PublicKeyPacket.GetEncodedContents().Length,
                Is.EqualTo((version == 6 ? 10 : 6) + material.Length));
            Assert.Catch<PgpException>(() => mock.GetKey());

            // the binding signature over the mock subkey verifies: the hashed key data is the original encoding
            PgpSignature binding = mock.GetSignaturesOfType(PgpSignature.SubkeyBinding).Single();
            binding.InitVerify(ring.GetPublicKey());
            Assert.That(binding.VerifyCertification(ring.GetPublicKey(), mock), Is.True);

            // the primary key verifies a signature (what the interoperability test suite checks)
            PgpSignature signature = Sign(primary, PgpSignature.BinaryDocument, g =>
            {
                g.Update(Message);
                return g.Generate();
            });
            signature.InitVerify(ring.GetPublicKey());
            signature.Update(Message);
            Assert.That(signature.Verify(), Is.True);

            // encryption picks the usable subkey; the mock one is not selected
            PgpEncryptionPreferences preferences = PgpEncryptionPreferences.Select(new[]{ ring });
            PgpEncryptedDataGenerator generator = preferences.CreateGenerator(Random);
            generator.AddMethod(ring.GetPublicKey(encryptionSubkey.KeyId));
            var output = new MemoryStream();
            using (Stream encOut = generator.Open(output, new byte[256]))
            using (Stream litOut = new PgpLiteralDataGenerator().Open(encOut, PgpLiteralData.Binary, "",
                Message.Length, DateTime.UtcNow))
            {
                litOut.Write(Message, 0, Message.Length);
            }
            var list = (PgpEncryptedDataList)new PgpObjectFactory(output.ToArray()).NextPgpObject();
            var encData = (PgpPublicKeyEncryptedData)list[0];
            var literal = (PgpLiteralData)new PgpObjectFactory(encData.GetDataStream(encryptionSubkey.PrivateKey))
                .NextPgpObject();
            Assert.That(Streams.ReadAll(literal.GetDataStream()), Is.EqualTo(Message));

            // a bundle holding the certificate looks keys up as usual
            var bundle = new PgpPublicKeyRingBundle(certificate);
            Assert.That(bundle.GetPublicKey(mock.KeyId).GetFingerprint(), Is.EqualTo(mock.GetFingerprint()));
        }

        /// <summary>Malformed key material on a curve that is supported is still an error.</summary>
        [Test]
        public void MalformedKeyOnKnownCurveIsRejected([Values(4, 6)] int version)
        {
            byte[] oid = SecObjectIdentifiers.SecP256r1.GetEncoded();
            byte[] material = Arrays.ConcatenateAll(new byte[]{ (byte)(oid.Length - 2) },
                Arrays.CopyOfRange(oid, 2, oid.Length), new byte[]{ 0xFF, 0xFF, 0x01 });
            var body = new MemoryStream();
            body.WriteByte((byte)version);
            body.Write(new byte[]{ 0x60, 0, 0, 0 }, 0, 4);
            body.WriteByte((byte)PublicKeyAlgorithmTag.ECDsa);
            if (version == 6)
            {
                body.Write(Org.BouncyCastle.Crypto.Utilities.Pack.UInt32_To_BE((uint)material.Length), 0, 4);
            }
            body.Write(material, 0, material.Length);
            byte[] packet = PgpV6TestUtilities.NewFormatPacket(PacketTag.PublicKey, body.ToArray());

            Assert.Catch<IOException>(() => new PgpPublicKeyRing(packet));
        }

        /// <summary>
        /// V6 key material on a known curve must not have trailing octets (exact length, RFC 9580 5.5.2.3).
        /// </summary>
        [Test]
        public void TrailingOctetsAfterKnownCurveKeyInVersion6()
        {
            var ecGen = new ECKeyPairGenerator();
            ecGen.Init(new ECKeyGenerationParameters(SecObjectIdentifiers.SecP256r1, Random));
            var pair = new PgpKeyPair(6, PublicKeyAlgorithmTag.ECDsa, ecGen.GenerateKeyPair(), DateTime.UtcNow);
            byte[] contents = pair.PublicKey.PublicKeyPacket.GetEncodedContents();
            Assert.That(new PgpPublicKeyRing(PgpV6TestUtilities.NewFormatPacket(PacketTag.PublicKey, contents))
                .GetPublicKey().GetKey(), Is.Not.Null);

            // add an octet to the key material and to its 4-octet length
            byte[] longer = Arrays.Append(contents, 0x00);
            uint keyLength = Org.BouncyCastle.Crypto.Utilities.Pack.BE_To_UInt32(longer, 6) + 1;
            Org.BouncyCastle.Crypto.Utilities.Pack.UInt32_To_BE(keyLength, longer, 6);
            Assert.Catch<IOException>(() =>
                new PgpPublicKeyRing(PgpV6TestUtilities.NewFormatPacket(PacketTag.PublicKey, longer)));
        }
    }
}
