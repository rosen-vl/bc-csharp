using System;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    /// <summary>Tests for the creation of version 6 keys (RFC 9580 5.5.2, 5.5.5).</summary>
    [TestFixture]
    public class PgpV6KeyGenerationTest
    {
        private static readonly SecureRandom Random = new SecureRandom();

        internal static AsymmetricCipherKeyPair GenerateEc(DerObjectIdentifier curve)
        {
            var gen = new ECKeyPairGenerator();
            gen.Init(new ECKeyGenerationParameters(curve, Random));
            return gen.GenerateKeyPair();
        }

        internal static AsymmetricCipherKeyPair GenerateRsa()
        {
            var gen = new RsaKeyPairGenerator();
            gen.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(0x10001), Random, 2048, 100));
            return gen.GenerateKeyPair();
        }

        internal static AsymmetricCipherKeyPair GenerateX(PublicKeyAlgorithmTag algorithm)
        {
            if (algorithm == PublicKeyAlgorithmTag.X25519)
            {
                var gen = new X25519KeyPairGenerator();
                gen.Init(new X25519KeyGenerationParameters(Random));
                return gen.GenerateKeyPair();
            }
            else
            {
                var gen = new X448KeyPairGenerator();
                gen.Init(new X448KeyGenerationParameters(Random));
                return gen.GenerateKeyPair();
            }
        }

        private static void CheckV6Key(PgpPublicKey key, PublicKeyAlgorithmTag algorithm)
        {
            Assert.That(key.Version, Is.EqualTo(6));
            Assert.That(key.Algorithm, Is.EqualTo(algorithm));
            Assert.That(key.GetFingerprint().Length, Is.EqualTo(32));
            Assert.That(key.KeyId, Is.EqualTo(FingerprintUtilities.KeyIDFromV6Fingerprint(key.GetFingerprint())));

            // the key packet is encoded and parsed without loss
            byte[] encoding = key.PublicKeyPacket.GetEncoded();
            var parsed = new PgpPublicKey(PgpV6TestUtilities.ReadPacket<PublicKeyPacket>(encoding));
            Assert.That(parsed.GetFingerprint(), Is.EqualTo(key.GetFingerprint()));
            Assert.That(parsed.KeyId, Is.EqualTo(key.KeyId));
            Assert.That(parsed.GetKey().IsPrivate, Is.False);
        }

        [Test]
        public void NativeCurveKeysForBothVersions()
        {
            foreach (int version in new[]{ 4, 6 })
            {
                foreach (var algorithm in new[]{ PublicKeyAlgorithmTag.Ed25519, PublicKeyAlgorithmTag.Ed448 })
                {
                    var pair = new PgpKeyPair(version, algorithm, PgpEdDsaV4SignatureTest.GenerateKeyPair(algorithm),
                        DateTime.UtcNow);
                    Assert.That(pair.PublicKey.Version, Is.EqualTo(version));
                    Assert.That(pair.PublicKey.Algorithm, Is.EqualTo(algorithm));
                    if (version == 6)
                    {
                        CheckV6Key(pair.PublicKey, algorithm);
                    }
                }

                foreach (var algorithm in new[]{ PublicKeyAlgorithmTag.X25519, PublicKeyAlgorithmTag.X448 })
                {
                    var pair = new PgpKeyPair(version, algorithm, GenerateX(algorithm), DateTime.UtcNow);
                    Assert.That(pair.PublicKey.Version, Is.EqualTo(version));
                    Assert.That(pair.PublicKey.IsEncryptionKey, Is.True);
                    if (version == 6)
                    {
                        CheckV6Key(pair.PublicKey, algorithm);
                    }
                }
            }
        }

        [Test]
        public void RsaAndEcdsaKeys()
        {
            var rsa = new PgpKeyPair(6, PublicKeyAlgorithmTag.RsaGeneral, GenerateRsa(), DateTime.UtcNow);
            CheckV6Key(rsa.PublicKey, PublicKeyAlgorithmTag.RsaGeneral);

            foreach (var curve in new[]
            {
                SecObjectIdentifiers.SecP256r1, SecObjectIdentifiers.SecP384r1, SecObjectIdentifiers.SecP521r1,
                TeleTrusTObjectIdentifiers.BrainpoolP256R1, TeleTrusTObjectIdentifiers.BrainpoolP512R1,
            })
            {
                var pair = new PgpKeyPair(6, PublicKeyAlgorithmTag.ECDsa, GenerateEc(curve), DateTime.UtcNow);
                CheckV6Key(pair.PublicKey, PublicKeyAlgorithmTag.ECDsa);
            }
        }

        // The KDF parameters of version 6 ECDH keys depend on the curve (RFC 9580 9.2).
        [Test]
        public void EcdhKeysHaveCurveSpecificKdfParameters()
        {
            var expected = new[]
            {
                (SecObjectIdentifiers.SecP256r1, HashAlgorithmTag.Sha256, SymmetricKeyAlgorithmTag.Aes128),
                (SecObjectIdentifiers.SecP384r1, HashAlgorithmTag.Sha384, SymmetricKeyAlgorithmTag.Aes192),
                (SecObjectIdentifiers.SecP521r1, HashAlgorithmTag.Sha512, SymmetricKeyAlgorithmTag.Aes256),
                (TeleTrusTObjectIdentifiers.BrainpoolP256R1, HashAlgorithmTag.Sha256, SymmetricKeyAlgorithmTag.Aes128),
                (TeleTrusTObjectIdentifiers.BrainpoolP384R1, HashAlgorithmTag.Sha384, SymmetricKeyAlgorithmTag.Aes192),
                (TeleTrusTObjectIdentifiers.BrainpoolP512R1, HashAlgorithmTag.Sha512, SymmetricKeyAlgorithmTag.Aes256),
            };

            foreach (var (curve, hash, wrap) in expected)
            {
                var v6 = new PgpKeyPair(6, PublicKeyAlgorithmTag.ECDH, GenerateEc(curve), DateTime.UtcNow);
                CheckV6Key(v6.PublicKey, PublicKeyAlgorithmTag.ECDH);

                var kdf = (ECDHPublicBcpgKey)v6.PublicKey.PublicKeyPacket.Key;
                Assert.That(kdf.HashAlgorithm, Is.EqualTo(hash), curve.ToString());
                Assert.That(kdf.SymmetricKeyAlgorithm, Is.EqualTo(wrap), curve.ToString());

                // version 4 keys keep the historic parameters
                var v4 = new PgpKeyPair(PublicKeyAlgorithmTag.ECDH, GenerateEc(curve), DateTime.UtcNow);
                var v4Kdf = (ECDHPublicBcpgKey)v4.PublicKey.PublicKeyPacket.Key;
                Assert.That(v4Kdf.HashAlgorithm, Is.EqualTo(HashAlgorithmTag.Sha256));
                Assert.That(v4Kdf.SymmetricKeyAlgorithm, Is.EqualTo(SymmetricKeyAlgorithmTag.Aes128));
            }

            // a curve without prescribed parameters
            Assert.Throws<ArgumentException>(() => new PgpKeyPair(6, PublicKeyAlgorithmTag.ECDH,
                GenerateEc(SecObjectIdentifiers.SecP256k1), DateTime.UtcNow));
        }

        // Algorithms that RFC 9580 forbids in version 6 keys.
        [Test]
        public void ForbiddenAlgorithmsAreRefusedForVersion6()
        {
            AsymmetricCipherKeyPair ed25519 = PgpEdDsaV4SignatureTest.GenerateKeyPair(PublicKeyAlgorithmTag.Ed25519);
            AsymmetricCipherKeyPair ed448 = PgpEdDsaV4SignatureTest.GenerateKeyPair(PublicKeyAlgorithmTag.Ed448);

            Assert.Throws<ArgumentException>(() =>
                new PgpPublicKey(6, PublicKeyAlgorithmTag.EdDsa_Legacy, ed25519.Public, DateTime.UtcNow));
            Assert.Throws<ArgumentException>(() =>
                new PgpPublicKey(6, PublicKeyAlgorithmTag.EdDsa_Legacy, ed448.Public, DateTime.UtcNow));
            Assert.Throws<ArgumentException>(() =>
                new PgpPublicKey(6, PublicKeyAlgorithmTag.ECDH, GenerateX(PublicKeyAlgorithmTag.X25519).Public,
                    DateTime.UtcNow));
            Assert.Throws<ArgumentException>(() =>
                new PgpPublicKey(6, PublicKeyAlgorithmTag.ECDH, GenerateX(PublicKeyAlgorithmTag.X448).Public,
                    DateTime.UtcNow));

            var dsaGen = new DsaKeyPairGenerator();
            var dsaParams = new DsaParametersGenerator();
            dsaParams.Init(1024, 80, Random);
            dsaGen.Init(new DsaKeyGenerationParameters(Random, dsaParams.GenerateParameters()));
            Assert.Throws<ArgumentException>(() =>
                new PgpPublicKey(6, PublicKeyAlgorithmTag.Dsa, dsaGen.GenerateKeyPair().Public, DateTime.UtcNow));

            var elGamalGen = new ElGamalKeyPairGenerator();
            elGamalGen.Init(new ElGamalKeyGenerationParameters(Random,
                new ElGamalParameters(BigInteger.ProbablePrime(512, Random), BigInteger.Two)));
            Assert.Throws<ArgumentException>(() => new PgpPublicKey(6, PublicKeyAlgorithmTag.ElGamalEncrypt,
                elGamalGen.GenerateKeyPair().Public, DateTime.UtcNow));

            // while the same keys are fine in version 4
            Assert.DoesNotThrow(() => new PgpPublicKey(4, PublicKeyAlgorithmTag.Dsa, dsaGen.GenerateKeyPair().Public,
                DateTime.UtcNow));
            Assert.DoesNotThrow(() => new PgpPublicKey(PublicKeyAlgorithmTag.EdDsa_Legacy, ed25519.Public,
                DateTime.UtcNow));
        }

        [Test]
        public void OnlyVersions4And6AreAccepted()
        {
            AsymmetricCipherKeyPair ed25519 = PgpEdDsaV4SignatureTest.GenerateKeyPair(PublicKeyAlgorithmTag.Ed25519);

            foreach (int version in new[]{ 0, 2, 3, 5, 7 })
            {
                Assert.Throws<ArgumentException>(() =>
                    new PgpPublicKey(version, PublicKeyAlgorithmTag.Ed25519, ed25519.Public, DateTime.UtcNow),
                    "version " + version);
            }
        }

        [Test]
        public void MLKemKeysForBothVersions()
        {
            foreach (int version in new[]{ 4, 6 })
            {
                var privateKey = new MLKem768X25519PrivateKeyParameters(Random);
                var pair = new PgpKeyPair(version, PublicKeyAlgorithmTag.MLKem768_X25519,
                    privateKey.GeneratePublicKey(), privateKey, DateTime.UtcNow);

                Assert.That(pair.PublicKey.Version, Is.EqualTo(version));
                Assert.That(pair.PublicKey.IsEncryptionKey, Is.True);
                if (version == 6)
                {
                    CheckV6Key(pair.PublicKey, PublicKeyAlgorithmTag.MLKem768_X25519);
                }
            }
        }

        [Test]
        public void AlgorithmMustMatchKeyType()
        {
            AsymmetricCipherKeyPair ed25519 = PgpEdDsaV4SignatureTest.GenerateKeyPair(PublicKeyAlgorithmTag.Ed25519);
            AsymmetricCipherKeyPair x25519 = GenerateX(PublicKeyAlgorithmTag.X25519);

            Assert.Throws<ArgumentException>(() =>
                new PgpPublicKey(6, PublicKeyAlgorithmTag.X25519, ed25519.Public, DateTime.UtcNow));
            Assert.Throws<ArgumentException>(() =>
                new PgpPublicKey(6, PublicKeyAlgorithmTag.Ed25519, x25519.Public, DateTime.UtcNow));
            Assert.Throws<ArgumentException>(() =>
                new PgpPublicKey(6, PublicKeyAlgorithmTag.MLKem768_X25519, x25519.Public, DateTime.UtcNow));
            Assert.Throws<ArgumentException>(() =>
                new PgpPublicKey(6, PublicKeyAlgorithmTag.RsaGeneral, x25519.Public, DateTime.UtcNow));
        }

        [Test]
        public void VersionedKeyPairsKeepPrivateKeys()
        {
            var pair = new PgpKeyPair(6, PublicKeyAlgorithmTag.Ed25519,
                PgpEdDsaV4SignatureTest.GenerateKeyPair(PublicKeyAlgorithmTag.Ed25519).Public,
                PgpEdDsaV4SignatureTest.GenerateKeyPair(PublicKeyAlgorithmTag.Ed25519).Private, DateTime.UtcNow);

            Assert.That(pair.KeyId, Is.EqualTo(pair.PublicKey.KeyId));
            Assert.That(pair.PrivateKey.KeyId, Is.EqualTo(pair.PublicKey.KeyId));
            Assert.That(pair.PrivateKey.PublicKeyPacket.Version, Is.EqualTo(6));
        }
    }
}
