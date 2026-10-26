using System;
using System.Linq;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    /// <summary>Tests for the expiry of keys that is kept in direct-key signatures (RFC 9580 10.1.1).</summary>
    [TestFixture]
    public class PgpV6KeyExpiryTest
    {
        private static readonly SecureRandom Random = new SecureRandom();

        private static readonly DateTime KeyTime = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        private static PgpKeyPair EdDsaPair(int version)
        {
            var generator = new Ed25519KeyPairGenerator();
            generator.Init(new Ed25519KeyGenerationParameters(Random));
            return new PgpKeyPair(version, PublicKeyAlgorithmTag.Ed25519, generator.GenerateKeyPair(), KeyTime);
        }

        private static PgpSignatureSubpacketVector Packets(long? expirySeconds, DateTime? created = null)
        {
            var generator = new PgpSignatureSubpacketGenerator();
            generator.SetKeyFlags(false, PgpKeyFlags.CanCertify | PgpKeyFlags.CanSign);
            if (expirySeconds.HasValue)
            {
                generator.SetKeyExpirationTime(false, expirySeconds.Value);
            }
            if (created.HasValue)
            {
                generator.SetSignatureCreationTime(false, created.Value);
            }
            return generator.Generate();
        }

        private static PgpSignature DirectKeySignature(PgpKeyPair pair, long? expirySeconds, DateTime created)
        {
            var generator = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha256);
            generator.InitSign(PgpSignature.DirectKey, pair.PrivateKey);
            generator.SetHashedSubpackets(Packets(expirySeconds, created));
            return generator.GenerateCertification(pair.PublicKey);
        }

        private static PgpPublicKeyRing Ring(PgpKeyRingGenerator generator) =>
            new PgpPublicKeyRing(generator.GeneratePublicKeyRing().GetEncoded());

        [Test]
        public void ExpiryFromDirectKeySignature()
        {
            var generator = new PgpKeyRingGenerator(EdDsaPair(6), HashAlgorithmTag.Sha256, Packets(1000), null,
                PgpSecretKeyProtection.None, Random);

            // the certification of the user ID does not repeat the expiry
            generator.AddUserId("expiry", PgpSignature.PositiveCertification, Packets(null), null);

            PgpPublicKeyRing ring = Ring(generator);
            Assert.That(ring.GetPublicKey().GetValidSeconds(), Is.EqualTo(1000));
            Assert.That(ring.GetPublicKey().GetValidSeconds(ring.GetPublicKey()), Is.EqualTo(1000));
            Assert.That(ring.GetValidSeconds(ring.GetPublicKey()), Is.EqualTo(1000));

            // a key without an expiry in its direct-key signature does not expire
            generator = new PgpKeyRingGenerator(EdDsaPair(6), HashAlgorithmTag.Sha256, Packets(null), null,
                PgpSecretKeyProtection.None, Random);
            generator.AddUserId("no expiry", PgpSignature.PositiveCertification, Packets(2000), null);
            Assert.That(Ring(generator).GetPublicKey().GetValidSeconds(), Is.EqualTo(0));
        }

        [Test]
        public void NewestDirectKeySignatureWins()
        {
            PgpKeyPair pair = EdDsaPair(6);
            PgpPublicKey key = pair.PublicKey;

            key = PgpPublicKey.AddCertification(key, DirectKeySignature(pair, 1000, KeyTime.AddDays(1)));
            Assert.That(key.GetValidSeconds(), Is.EqualTo(1000));

            key = PgpPublicKey.AddCertification(key, DirectKeySignature(pair, 5000, KeyTime.AddDays(3)));
            key = PgpPublicKey.AddCertification(key, DirectKeySignature(pair, 3000, KeyTime.AddDays(2)));
            Assert.That(key.GetValidSeconds(), Is.EqualTo(5000));

            key = PgpPublicKey.AddCertification(key, DirectKeySignature(pair, null, KeyTime.AddDays(4)));
            Assert.That(key.GetValidSeconds(), Is.EqualTo(0));
        }

        [Test]
        public void Version4KeysKeepTheirPrecedence()
        {
            var generator = new PgpKeyRingGenerator(EdDsaPair(4), HashAlgorithmTag.Sha256, Packets(1000), null,
                PgpSecretKeyProtection.None, Random);
            generator.AddUserId("expiry", PgpSignature.PositiveCertification, Packets(2000), null);

            Assert.That(Ring(generator).GetPublicKey().GetValidSeconds(), Is.EqualTo(2000));

            // without a certification, the direct-key signature is used
            generator = new PgpKeyRingGenerator(EdDsaPair(4), HashAlgorithmTag.Sha256, Packets(1000), null,
                PgpSecretKeyProtection.None, Random);
            Assert.That(Ring(generator).GetPublicKey().GetValidSeconds(), Is.EqualTo(1000));
        }

        /// <summary>The expiry of subkeys comes from their binding signatures.</summary>
        [Test]
        public void SubkeyExpiry()
        {
            var generator = new PgpKeyRingGenerator(EdDsaPair(6), HashAlgorithmTag.Sha256, Packets(1000), null,
                PgpSecretKeyProtection.None, Random);

            var x25519 = new X25519KeyPairGenerator();
            x25519.Init(new X25519KeyGenerationParameters(Random));
            var subkey = new PgpKeyPair(6, PublicKeyAlgorithmTag.X25519, x25519.GenerateKeyPair(), KeyTime);

            var subpackets = new PgpSignatureSubpacketGenerator();
            subpackets.SetKeyFlags(false, PgpKeyFlags.CanEncryptCommunications);
            subpackets.SetKeyExpirationTime(false, 400);
            generator.AddSubKey(subkey, subpackets.Generate(), null);

            PgpPublicKeyRing ring = Ring(generator);
            PgpPublicKey[] keys = ring.GetPublicKeys().ToArray();
            Assert.That(keys[0].GetValidSeconds(), Is.EqualTo(1000));
            Assert.That(keys[1].GetValidSeconds(), Is.EqualTo(400));
            Assert.That(keys[1].GetValidSeconds(keys[0]), Is.EqualTo(400));
        }
    }
}
