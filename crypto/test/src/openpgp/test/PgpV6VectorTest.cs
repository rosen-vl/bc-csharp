using System;
using System.Linq;

using NUnit.Framework;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    // The key and signature vectors of RFC 9580 Appendix A.
    [TestFixture]
    public class PgpV6VectorTest
    {
        private const string PrimaryFingerprint = "cb186c4f0609a697e4d52dfa6c722b0c1f1e27c18a56708f6525ec27bad9acc9";
        private const string SubkeyFingerprint = "12c83f1e706f6308fe151a417743a1f033790e93e9978488d1db378da9930885";

        private static readonly string[] Version6Files =
        {
            "a3-v6-certificate.asc", "a4-v6-secret-key.asc", "a5-v6-locked-secret-key.asc",
        };

        // The key rings of the RFC re-encode to the same octets.
        [Test]
        public void KeyRingsReEncodeExactly()
        {
            byte[] certificate = PgpV6TestUtilities.LoadRfc9580("a3-v6-certificate.asc");
            Assert.That(new PgpPublicKeyRing(certificate).GetEncoded(), Is.EqualTo(certificate));

            foreach (string file in new[]{ "a4-v6-secret-key.asc", "a5-v6-locked-secret-key.asc" })
            {
                byte[] secretKey = PgpV6TestUtilities.LoadRfc9580(file);
                Assert.That(new PgpSecretKeyRing(secretKey).GetEncoded(), Is.EqualTo(secretKey), file);
            }

            byte[] legacy = PgpV6TestUtilities.LoadRfc9580("a1-v4-ed25519legacy-key.asc");
            Assert.That(new PgpPublicKeyRing(legacy).GetEncoded(), Is.EqualTo(legacy));
        }

        [Test]
        public void FingerprintsAndKeyIds()
        {
            PgpPublicKey[][] rings =
            {
                new PgpPublicKeyRing(PgpV6TestUtilities.LoadRfc9580("a3-v6-certificate.asc")).GetPublicKeys().ToArray(),
                new PgpSecretKeyRing(PgpV6TestUtilities.LoadRfc9580("a4-v6-secret-key.asc")).GetPublicKeys().ToArray(),
                new PgpSecretKeyRing(PgpV6TestUtilities.LoadRfc9580("a5-v6-locked-secret-key.asc"))
                    .GetPublicKeys().ToArray(),
            };

            foreach (PgpPublicKey[] keys in rings)
            {
                Assert.That(keys.Length, Is.EqualTo(2));
                Assert.That(keys.All(k => k.Version == 6), Is.True);

                Assert.That(Hex.ToHexString(keys[0].GetFingerprint()), Is.EqualTo(PrimaryFingerprint));
                Assert.That(Hex.ToHexString(keys[1].GetFingerprint()), Is.EqualTo(SubkeyFingerprint));

                // the key ID is the leftmost 64 bits of a version 6 fingerprint
                Assert.That(keys[0].KeyId, Is.EqualTo(unchecked((long)0xcb186c4f0609a697UL)));
                Assert.That(keys[1].KeyId, Is.EqualTo(unchecked((long)0x12c83f1e706f6308UL)));

                Assert.That(keys[0].Algorithm, Is.EqualTo(PublicKeyAlgorithmTag.Ed25519));
                Assert.That(keys[1].Algorithm, Is.EqualTo(PublicKeyAlgorithmTag.X25519));
                Assert.That(keys[1].IsEncryptionKey, Is.True);
            }
        }

        [Test]
        public void ThreeFormsOfTheSameKey()
        {
            var certificate = new PgpPublicKeyRing(PgpV6TestUtilities.LoadRfc9580("a3-v6-certificate.asc"));
            var unlocked = new PgpSecretKeyRing(PgpV6TestUtilities.LoadRfc9580("a4-v6-secret-key.asc"));
            var locked = new PgpSecretKeyRing(PgpV6TestUtilities.LoadRfc9580("a5-v6-locked-secret-key.asc"));

            // the public parts of the secret key rings are the certificate, key by key
            PgpPublicKey[] expected = certificate.GetPublicKeys().ToArray();
            foreach (PgpSecretKeyRing ring in new[]{ unlocked, locked })
            {
                PgpPublicKey[] actual = ring.GetPublicKeys().ToArray();
                for (int i = 0; i < expected.Length; ++i)
                {
                    Assert.That(actual[i].PublicKeyPacket.GetEncoded(),
                        Is.EqualTo(expected[i].PublicKeyPacket.GetEncoded()));
                }
            }

            // the unlocked key has no protection, the other has AEAD protection (the A.5 unlocking is tested with
            // the protection fixture because its Argon2 parameters need 2 GiB)
            Assert.That(unlocked.GetSecretKey().KeyEncryptionAlgorithm, Is.EqualTo(SymmetricKeyAlgorithmTag.Null));
            Assert.That(locked.GetSecretKey().KeyEncryptionAlgorithm, Is.EqualTo(SymmetricKeyAlgorithmTag.Aes256));
        }

        // The self-signatures of RFC 9580 A.3 verify and are of version 6.
        [Test]
        public void CertificateSelfSignatures()
        {
            var ring = new PgpPublicKeyRing(PgpV6TestUtilities.LoadRfc9580("a3-v6-certificate.asc"));
            PgpPublicKey primary = ring.GetPublicKey();
            PgpPublicKey subkey = ring.GetPublicKeys().Last();

            PgpSignature direct = primary.GetKeySignatures().Cast<PgpSignature>().Single();
            Assert.That(direct.Version, Is.EqualTo(6));
            Assert.That(direct.SignatureType, Is.EqualTo(PgpSignature.DirectKey));
            direct.InitVerify(primary);
            Assert.That(direct.VerifyCertification(primary), Is.True);

            PgpSignature binding = subkey.GetSignaturesOfType(PgpSignature.SubkeyBinding).Cast<PgpSignature>().Single();
            Assert.That(binding.Version, Is.EqualTo(6));
            binding.InitVerify(primary);
            Assert.That(binding.VerifyCertification(primary, subkey), Is.True);

            // and not for a different pair of keys
            binding.InitVerify(primary);
            Assert.That(binding.VerifyCertification(primary, primary), Is.False);
        }

        // The version 4 EdDSALegacy key and signature of RFC 9580 A.1 and A.2.
        [Test]
        public void Version4Ed25519LegacySignature()
        {
            var ring = new PgpPublicKeyRing(PgpV6TestUtilities.LoadRfc9580("a1-v4-ed25519legacy-key.asc"));
            PgpPublicKey key = ring.GetPublicKey();
            Assert.That(key.Version, Is.EqualTo(4));
            Assert.That(key.Algorithm, Is.EqualTo(PublicKeyAlgorithmTag.EdDsa_Legacy));

            var signatures = (PgpSignatureList)new PgpObjectFactory(
                PgpV6TestUtilities.LoadRfc9580("a2-v4-ed25519legacy-signature.asc")).NextPgpObject();
            PgpSignature signature = signatures[0];
            Assert.That(signature.Version, Is.EqualTo(4));
            Assert.That(signature.HashAlgorithm, Is.EqualTo(HashAlgorithmTag.Sha256));
            Assert.That(signature.KeyId, Is.EqualTo(key.KeyId));

            // r and s of the RFC
            Assert.That(Hex.ToHexString(signature.GetSignature()), Is.EqualTo(
                "56f90cca98e2102637bd983fdb16c131dfd27ed82bf4dde5606e0d756aed3366"
                + "d09c4fa11527f038e0f57f2201d82f2ea2c9033265fa6ceb489e854bae61b404"));

            signature.InitVerify(key);
            signature.Update(Strings.ToUtf8ByteArray("OpenPGP"));
            Assert.That(signature.Verify(), Is.True);

            signature.InitVerify(key);
            signature.Update(Strings.ToUtf8ByteArray("OpenPGp"));
            Assert.That(signature.Verify(), Is.False);
        }
    }
}
