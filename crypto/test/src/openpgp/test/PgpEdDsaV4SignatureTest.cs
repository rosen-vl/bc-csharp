using System;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    /// <summary>Tests for version 4 signatures made with Ed25519 and Ed448 keys (RFC 9580 5.2.3.4, 5.2.3.5).</summary>
    [TestFixture]
    public class PgpEdDsaV4SignatureTest
    {
        private static readonly SecureRandom Random = new SecureRandom();

        private static readonly byte[] Data = Strings.ToUtf8ByteArray("data to be signed");

        internal static AsymmetricCipherKeyPair GenerateKeyPair(PublicKeyAlgorithmTag algorithm)
        {
            switch (algorithm)
            {
            case PublicKeyAlgorithmTag.Ed25519:
            {
                var gen = new Ed25519KeyPairGenerator();
                gen.Init(new Ed25519KeyGenerationParameters(Random));
                return gen.GenerateKeyPair();
            }
            case PublicKeyAlgorithmTag.Ed448:
            {
                var gen = new Ed448KeyPairGenerator();
                gen.Init(new Ed448KeyGenerationParameters(Random));
                return gen.GenerateKeyPair();
            }
            default:
                throw new ArgumentException();
            }
        }

        private static readonly object[][] Algorithms =
        {
            new object[]{ PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha256, 64 },
            new object[]{ PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha512, 64 },
            new object[]{ PublicKeyAlgorithmTag.Ed448, HashAlgorithmTag.Sha512, 114 },
        };

        private static PgpSignature Sign(PgpKeyPair keyPair, HashAlgorithmTag hash, int signatureType,
            SecureRandom random)
        {
            var generator = new PgpSignatureGenerator(keyPair.PublicKey.Algorithm, hash);
            generator.InitSign(signatureType, keyPair.PrivateKey, random);
            generator.Update(Data);
            return generator.Generate();
        }

        private static bool Verify(PgpSignature signature, PgpPublicKey key, byte[] data)
        {
            signature.InitVerify(key);
            signature.Update(data);
            return signature.Verify();
        }

        [TestCaseSource(nameof(Algorithms))]
        public void SignAndVerify(PublicKeyAlgorithmTag algorithm, HashAlgorithmTag hash, int signatureLength)
        {
            var keyPair = new PgpKeyPair(algorithm, GenerateKeyPair(algorithm), DateTime.UtcNow);

            foreach (SecureRandom random in new[]{ null, Random })
            {
                PgpSignature signature = Sign(keyPair, hash, PgpSignature.BinaryDocument, random);

                Assert.That(signature.Version, Is.EqualTo(4));
                Assert.That(signature.KeyAlgorithm, Is.EqualTo(algorithm));
                Assert.That(signature.KeyId, Is.EqualTo(keyPair.KeyId));
                Assert.That(Verify(signature, keyPair.PublicKey, Data), Is.True);
                Assert.That(Verify(signature, keyPair.PublicKey, Strings.ToUtf8ByteArray("other data")), Is.False);
            }
        }

        [TestCaseSource(nameof(Algorithms))]
        public void SignatureIsEncodedRaw(PublicKeyAlgorithmTag algorithm, HashAlgorithmTag hash, int signatureLength)
        {
            var keyPair = new PgpKeyPair(algorithm, GenerateKeyPair(algorithm), DateTime.UtcNow);

            PgpSignature signature = Sign(keyPair, hash, PgpSignature.BinaryDocument, Random);
            byte[] encoding = signature.GetEncoded();

            var packet = PgpV6TestUtilities.ReadPacket<SignaturePacket>(encoding);
            Assert.That(packet.GetSignature(), Is.Null);
            Assert.That(packet.GetSignatureBytes().Length, Is.EqualTo(signatureLength));
            Assert.That(packet.GetSalt(), Is.Null);

            // the packet is made of the header, hashed and unhashed areas, digest prefix and the raw signature
            Assert.That(Arrays.AreEqual(encoding, packet.GetEncoded()), Is.True);

            // an encoded signature verifies after parsing
            var parsed = (PgpSignatureList)new PgpObjectFactory(encoding).NextPgpObject();
            Assert.That(Verify(parsed[0], keyPair.PublicKey, Data), Is.True);
        }

        [Test]
        public void CertificationsAndTextSignatures()
        {
            var keyPair = new PgpKeyPair(PublicKeyAlgorithmTag.Ed25519,
                GenerateKeyPair(PublicKeyAlgorithmTag.Ed25519), DateTime.UtcNow);

            var generator = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha256);
            generator.InitSign(PgpSignature.PositiveCertification, keyPair.PrivateKey);
            PgpSignature certification = generator.GenerateCertification("Alice <alice@example.org>",
                keyPair.PublicKey);

            certification.InitVerify(keyPair.PublicKey);
            Assert.That(certification.VerifyCertification("Alice <alice@example.org>", keyPair.PublicKey), Is.True);

            // canonical text: line ending conversion is applied before hashing
            var textGenerator = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha512);
            textGenerator.InitSign(PgpSignature.CanonicalTextDocument, keyPair.PrivateKey);
            textGenerator.Update(Strings.ToUtf8ByteArray("line one\nline two\r\n"));
            PgpSignature textSignature = textGenerator.Generate();

            Assert.That(Verify(textSignature, keyPair.PublicKey, Strings.ToUtf8ByteArray("line one\r\nline two\n")),
                Is.True);
        }

        // The minimum digest sizes of RFC 9580 5.2.3.4 and 5.2.3.5 are enforced.
        [Test]
        public void WeakHashAlgorithmsAreRefused()
        {
            var ed25519 = new PgpKeyPair(PublicKeyAlgorithmTag.Ed25519,
                GenerateKeyPair(PublicKeyAlgorithmTag.Ed25519), DateTime.UtcNow);
            var ed448 = new PgpKeyPair(PublicKeyAlgorithmTag.Ed448, GenerateKeyPair(PublicKeyAlgorithmTag.Ed448),
                DateTime.UtcNow);

            foreach (var hash in new[]{ HashAlgorithmTag.Sha1, HashAlgorithmTag.Sha224, HashAlgorithmTag.MD5 })
            {
                var generator = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, hash);
                Assert.Throws<PgpException>(() => generator.InitSign(PgpSignature.BinaryDocument, ed25519.PrivateKey),
                    hash.ToString());
            }

            foreach (var hash in new[]{ HashAlgorithmTag.Sha1, HashAlgorithmTag.Sha256, HashAlgorithmTag.Sha384 })
            {
                var generator = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed448, hash);
                Assert.Throws<PgpException>(() => generator.InitSign(PgpSignature.BinaryDocument, ed448.PrivateKey),
                    hash.ToString());
            }
        }

        [TestCase(PublicKeyAlgorithmTag.Ed25519, false)]
        [TestCase(PublicKeyAlgorithmTag.Ed25519, true)]
        [TestCase(PublicKeyAlgorithmTag.Ed448, false)]
        [TestCase(PublicKeyAlgorithmTag.Ed448, true)]
        public void KeysRoundTripThroughKeyRings(PublicKeyAlgorithmTag algorithm, bool protect)
        {
            var keyPair = new PgpKeyPair(algorithm, GenerateKeyPair(algorithm), DateTime.UtcNow);
            char[] password = protect ? "secret".ToCharArray() : new char[0];

            var ringGenerator = new PgpKeyRingGenerator(PgpSignature.PositiveCertification, keyPair, "edwards",
                protect ? SymmetricKeyAlgorithmTag.Aes256 : SymmetricKeyAlgorithmTag.Null, HashAlgorithmTag.Sha512,
                password, true, null, null, Random);

            var secretRing = new PgpSecretKeyRing(ringGenerator.GenerateSecretKeyRing().GetEncoded());
            var publicRing = new PgpPublicKeyRing(ringGenerator.GeneratePublicKeyRing().GetEncoded());

            PgpPublicKey publicKey = publicRing.GetPublicKey();
            Assert.That(publicKey.Algorithm, Is.EqualTo(algorithm));
            Assert.That(publicKey.Version, Is.EqualTo(4));
            Assert.That(publicKey.GetKey().IsPrivate, Is.False);

            // the self-certification verifies
            PgpSignature selfSignature = null;
            foreach (PgpSignature s in publicKey.GetSignatures())
            {
                selfSignature = s;
            }
            selfSignature.InitVerify(publicKey);
            Assert.That(selfSignature.VerifyCertification("edwards", publicKey), Is.True);

            PgpPrivateKey privateKey = secretRing.GetSecretKey().ExtractPrivateKey(password);
            var keyPairAgain = new PgpKeyPair(publicKey, privateKey);
            PgpSignature signature = Sign(keyPairAgain, HashAlgorithmTag.Sha512, PgpSignature.BinaryDocument, Random);
            Assert.That(Verify(signature, publicKey, Data), Is.True);

            if (protect)
            {
                Assert.Throws<PgpException>(() => secretRing.GetSecretKey().ExtractPrivateKey("wrong".ToCharArray()));
            }
        }

        /// <summary>The key type must match the algorithm tag.</summary>
        [Test]
        public void PublicKeyMappingRejectsMismatches()
        {
            AsymmetricCipherKeyPair ed25519 = GenerateKeyPair(PublicKeyAlgorithmTag.Ed25519);
            AsymmetricCipherKeyPair ed448 = GenerateKeyPair(PublicKeyAlgorithmTag.Ed448);

            Assert.Throws<ArgumentException>(() => new PgpPublicKey(PublicKeyAlgorithmTag.Ed448, ed25519.Public,
                DateTime.UtcNow));
            Assert.Throws<ArgumentException>(() => new PgpPublicKey(PublicKeyAlgorithmTag.Ed25519, ed448.Public,
                DateTime.UtcNow));
            Assert.Throws<ArgumentException>(() => new PgpPublicKey(PublicKeyAlgorithmTag.ECDsa, ed25519.Public,
                DateTime.UtcNow));

            // the legacy form is still available for version 4 keys
            var legacy = new PgpPublicKey(PublicKeyAlgorithmTag.EdDsa_Legacy, ed25519.Public, DateTime.UtcNow);
            Assert.That(legacy.PublicKeyPacket.Key, Is.InstanceOf<EdDsaPublicBcpgKey>());

            var native = new PgpPublicKey(PublicKeyAlgorithmTag.Ed25519, ed25519.Public, DateTime.UtcNow);
            Assert.That(native.PublicKeyPacket.Key, Is.InstanceOf<Ed25519PublicBcpgKey>());
            Assert.That(native.GetKey(), Is.EqualTo(ed25519.Public));
        }

        /// <summary>The secret key material is checked against the public key when it is decoded.</summary>
        [Test]
        public void MismatchedSecretKeyIsDetected()
        {
            var first = new PgpKeyPair(PublicKeyAlgorithmTag.Ed25519, GenerateKeyPair(PublicKeyAlgorithmTag.Ed25519),
                DateTime.UtcNow);
            var second = GenerateKeyPair(PublicKeyAlgorithmTag.Ed25519);

            // a secret key of one key pair with the public key of another
            var mismatched = new PgpKeyPair(PublicKeyAlgorithmTag.Ed25519, first.PublicKey.GetKey(), second.Private,
                DateTime.UtcNow);
            var ringGenerator = new PgpKeyRingGenerator(PgpSignature.PositiveCertification, mismatched, "mismatch",
                SymmetricKeyAlgorithmTag.Null, HashAlgorithmTag.Sha256, new char[0], false, null, null, Random);

            PgpSecretKey secretKey = ringGenerator.GenerateSecretKeyRing().GetSecretKey();
            Assert.Throws<PgpException>(() => secretKey.ExtractPrivateKey(new char[0]));
        }
    }
}
