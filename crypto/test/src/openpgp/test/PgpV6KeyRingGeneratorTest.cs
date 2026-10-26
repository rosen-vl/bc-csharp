using System;
using System.Collections.Generic;
using System.Linq;

using NUnit.Framework;

using Org.BouncyCastle.Bcpg.Sig;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    /// <summary>Tests for key rings made with direct-key signatures (RFC 9580 10.1).</summary>
    [TestFixture]
    public class PgpV6KeyRingGeneratorTest
    {
        private static readonly SecureRandom Random = new SecureRandom();

        private static readonly byte[] PassPhrase = Strings.ToUtf8ByteArray("a pass phrase for the ring");

        private static S2k.Argon2Params SmallArgon2() => new S2k.Argon2Params(1, 1, 10, Random);

        private static PgpKeyPair EdDsaPair(int version)
        {
            var generator = new Ed25519KeyPairGenerator();
            generator.Init(new Ed25519KeyGenerationParameters(Random));
            return new PgpKeyPair(version, PublicKeyAlgorithmTag.Ed25519, generator.GenerateKeyPair(),
                DateTime.UtcNow);
        }

        private static PgpKeyPair X25519Pair(int version)
        {
            var generator = new X25519KeyPairGenerator();
            generator.Init(new X25519KeyGenerationParameters(Random));
            return new PgpKeyPair(version, PublicKeyAlgorithmTag.X25519, generator.GenerateKeyPair(),
                DateTime.UtcNow);
        }

        private static PgpSignatureSubpacketVector Flags(int flags)
        {
            var generator = new PgpSignatureSubpacketGenerator();
            generator.SetKeyFlags(false, flags);
            return generator.Generate();
        }

        private static PgpSignatureSubpacketVector Preferences()
        {
            var generator = new PgpSignatureSubpacketGenerator();
            generator.SetKeyFlags(false, PgpKeyFlags.CanCertify | PgpKeyFlags.CanSign);
            generator.SetPreferredSymmetricAlgorithms(false,
                new[]{ (int)SymmetricKeyAlgorithmTag.Aes256, (int)SymmetricKeyAlgorithmTag.Aes128 });
            generator.SetPreferredHashAlgorithms(false, new[]{ (int)HashAlgorithmTag.Sha512 });
            generator.SetFeature(false, (byte)(Features.FEATURE_MODIFICATION_DETECTION | Features.FEATURE_SEIPD_V2));
            return generator.Generate();
        }

        private static PgpKeyRingGenerator NewGenerator(int version, PgpSecretKeyProtection protection = null,
            HashAlgorithmTag hash = HashAlgorithmTag.Sha256)
        {
            return new PgpKeyRingGenerator(EdDsaPair(version), hash, Preferences(), null,
                protection ?? PgpSecretKeyProtection.None, Random);
        }

        /// <summary>
        /// The direct-key signature and the user ID certifications share one creation time, however long the
        /// protection of the keys takes, so that implementations that take the key flags of the primary key from its
        /// newest self-signature (Bouncy Castle Java does) find those of the direct-key signature. A binding signature
        /// is not older than its subkey, and a creation time given by the caller is kept.
        /// </summary>
        [Test]
        public void SelfSignaturesShareOneCreationTime()
        {
            var protection = PgpSecretKeyProtection.AeadArgon2(SymmetricKeyAlgorithmTag.Aes256, AeadAlgorithmTag.Ocb,
                new S2k.Argon2Params(1, 4, 16, Random), PassPhrase);
            PgpKeyRingGenerator generator = NewGenerator(6, protection);

            // protecting each key takes a while, so the signatures below would otherwise differ by seconds
            System.Threading.Thread.Sleep(1100);
            generator.AddUserId("alice <alice@example.org>", PgpSignature.PositiveCertification, null, null);
            generator.AddSubKey(X25519Pair(6), Flags(PgpKeyFlags.CanEncryptCommunications), null);
            generator.AddSubKey(EdDsaPair(6), Flags(PgpKeyFlags.CanSign), null);

            System.Threading.Thread.Sleep(1100);
            PgpKeyPair laterSubkey = X25519Pair(6);
            generator.AddSubKey(laterSubkey, Flags(PgpKeyFlags.CanEncryptStorage), null);

            DateTime given = new DateTime(2030, 1, 2, 3, 4, 5, DateTimeKind.Utc);
            var explicitTime = new PgpSignatureSubpacketGenerator();
            explicitTime.SetKeyFlags(false, PgpKeyFlags.CanEncryptStorage);
            explicitTime.SetSignatureCreationTime(false, given);
            generator.AddSubKey(X25519Pair(6), explicitTime.Generate(), null);

            PgpPublicKeyRing ring = new PgpPublicKeyRing(generator.GeneratePublicKeyRing().GetEncoded());
            PgpPublicKey primary = ring.GetPublicKey();
            DateTime directKeyTime = primary.GetSignaturesOfType(PgpSignature.DirectKey).Cast<PgpSignature>()
                .Single().CreationTime;
            PgpSignature certification = primary.GetSignaturesForId("alice <alice@example.org>").Cast<PgpSignature>()
                .Single();
            Assert.That(certification.CreationTime, Is.EqualTo(directKeyTime));
            Assert.That(directKeyTime, Is.GreaterThanOrEqualTo(primary.CreationTime));

            PgpPublicKey[] subkeys = ring.GetPublicKeys().Skip(1).ToArray();
            Assert.That(subkeys.Length, Is.EqualTo(4));
            for (int i = 0; i < subkeys.Length; ++i)
            {
                PgpSignature binding = subkeys[i].GetSignaturesOfType(PgpSignature.SubkeyBinding).Cast<PgpSignature>()
                    .Single();
                DateTime expected = i == 3 ? given
                    : subkeys[i].CreationTime > directKeyTime ? subkeys[i].CreationTime
                    : directKeyTime;
                Assert.That(binding.CreationTime, Is.EqualTo(expected), "subkey " + i);
                Assert.That(binding.CreationTime, Is.GreaterThanOrEqualTo(subkeys[i].CreationTime), "subkey " + i);
                CheckBinding(primary, subkeys[i], embeddedExpected: i == 1);
            }
            Assert.That(subkeys[2].CreationTime, Is.GreaterThan(directKeyTime), "the subkey made later");
            PgpSignature backSignature = subkeys[1].GetSignaturesOfType(PgpSignature.SubkeyBinding)
                .Cast<PgpSignature>().Single().GetHashedSubPackets().GetEmbeddedSignatures()[0];
            Assert.That(backSignature.CreationTime, Is.GreaterThanOrEqualTo(subkeys[1].CreationTime));
        }

        private static void CheckBinding(PgpPublicKey primary, PgpPublicKey subkey, bool embeddedExpected)
        {
            PgpSignature binding = subkey.GetSignaturesOfType(PgpSignature.SubkeyBinding).Cast<PgpSignature>().Single();
            Assert.That(binding.Version, Is.EqualTo(subkey.Version));
            binding.InitVerify(primary);
            Assert.That(binding.VerifyCertification(primary, subkey), Is.True);

            PgpSignatureList embedded = binding.GetHashedSubPackets().GetEmbeddedSignatures();
            if (embeddedExpected)
            {
                Assert.That(embedded.Count, Is.EqualTo(1));
                Assert.That(embedded[0].SignatureType, Is.EqualTo(PgpSignature.PrimaryKeyBinding));
                Assert.That(embedded[0].Version, Is.EqualTo(subkey.Version));
                embedded[0].InitVerify(subkey);
                Assert.That(embedded[0].VerifyCertification(primary, subkey), Is.True);
            }
            else
            {
                Assert.That(embedded.Count, Is.EqualTo(0));
            }
        }

        // RFC 9580 5.2.1.8: the binding of a signing subkey embeds a primary key binding signature, also for a subkey
        // without key flags whose algorithm can sign, in both kinds of generator
        [Test]
        public void SigningSubkeysEmbedPrimaryKeyBindings()
        {
            PgpKeyRingGenerator generator = NewGenerator(6);
            PgpKeyPair noFlags = EdDsaPair(6), encryption = X25519Pair(6);
            generator.AddSubKey(noFlags, null, null);
            generator.AddSubKey(encryption, Flags(PgpKeyFlags.CanEncryptCommunications), null);
            var ring = new PgpPublicKeyRing(generator.GeneratePublicKeyRing().GetEncoded());
            CheckBinding(ring.GetPublicKey(), ring.GetPublicKey(noFlags.KeyId), true);
            CheckBinding(ring.GetPublicKey(), ring.GetPublicKey(encryption.KeyId), false);

            var classic = new PgpKeyRingGenerator(PgpSignature.PositiveCertification, EdDsaPair(4), "v4",
                SymmetricKeyAlgorithmTag.Null, HashAlgorithmTag.Sha256, new char[0], true, null, null, Random);
            PgpKeyPair signing = EdDsaPair(4), unflagged = EdDsaPair(4);
            classic.AddSubKey(signing, Flags(PgpKeyFlags.CanSign), null);
            classic.AddSubKey(unflagged, null, null);
            ring = new PgpPublicKeyRing(classic.GeneratePublicKeyRing().GetEncoded());
            CheckBinding(ring.GetPublicKey(), ring.GetPublicKey(signing.KeyId), true);

            CheckBinding(ring.GetPublicKey(), ring.GetPublicKey(unflagged.KeyId), true);
        }

        [Test]
        public void Version6RingWithAllKindsOfSubkeys()
        {
            PgpKeyRingGenerator generator = NewGenerator(6);
            generator.AddUserId("Alice <alice@example.org>", PgpSignature.PositiveCertification, Flags(0), null);
            generator.AddUserId("Alice <alice@example.com>", PgpSignature.PositiveCertification, null, null);

            generator.AddSubKey(X25519Pair(6), Flags(PgpKeyFlags.CanEncryptCommunications), null);
            generator.AddSubKey(EdDsaPair(6), Flags(PgpKeyFlags.CanSign), null);

            var publicRing = new PgpPublicKeyRing(generator.GeneratePublicKeyRing().GetEncoded());
            PgpPublicKey primary = publicRing.GetPublicKey();
            Assert.That(primary.Version, Is.EqualTo(6));

            // the direct-key signature
            PgpSignature direct = primary.GetKeySignatures().Cast<PgpSignature>().Single();
            Assert.That(direct.SignatureType, Is.EqualTo(PgpSignature.DirectKey));
            Assert.That(direct.Version, Is.EqualTo(6));
            direct.InitVerify(primary);
            Assert.That(direct.VerifyCertification(primary), Is.True);

            // the user IDs
            Assert.That(primary.GetUserIds().Cast<string>().ToArray(),
                Is.EqualTo(new[]{ "Alice <alice@example.org>", "Alice <alice@example.com>" }));
            foreach (string id in primary.GetUserIds())
            {
                PgpSignature certification = primary.GetSignaturesForId(id).Single();
                Assert.That(certification.Version, Is.EqualTo(6));
                certification.InitVerify(primary);
                Assert.That(certification.VerifyCertification(id, primary), Is.True, id);
            }

            // the subkeys
            PgpPublicKey[] subkeys = publicRing.GetPublicKeys().Skip(1).ToArray();
            Assert.That(subkeys.Length, Is.EqualTo(2));
            Assert.That(subkeys.All(k => k.Version == 6), Is.True);
            CheckBinding(primary, subkeys[0], embeddedExpected: false);
            CheckBinding(primary, subkeys[1], embeddedExpected: true);
        }

        [Test]
        public void Version4Ring()
        {
            PgpKeyRingGenerator generator = NewGenerator(4, hash: HashAlgorithmTag.Sha512);
            generator.AddUserId("Bob <bob@example.org>", PgpSignature.PositiveCertification, null, null);
            generator.AddSubKey(X25519Pair(4), Flags(PgpKeyFlags.CanEncryptStorage), null);
            generator.AddSubKey(EdDsaPair(4), Flags(PgpKeyFlags.CanSign), null);

            var publicRing = new PgpPublicKeyRing(generator.GeneratePublicKeyRing().GetEncoded());
            PgpPublicKey primary = publicRing.GetPublicKey();
            Assert.That(primary.Version, Is.EqualTo(4));

            PgpSignature direct = primary.GetKeySignatures().Cast<PgpSignature>().Single();
            direct.InitVerify(primary);
            Assert.That(direct.VerifyCertification(primary), Is.True);

            PgpPublicKey[] subkeys = publicRing.GetPublicKeys().Skip(1).ToArray();
            CheckBinding(primary, subkeys[0], embeddedExpected: false);
            CheckBinding(primary, subkeys[1], embeddedExpected: true);
        }

        [Test]
        public void SubkeyVersionMustMatch()
        {
            PgpKeyRingGenerator v6 = NewGenerator(6);
            Assert.Throws<ArgumentException>(() => v6.AddSubKey(X25519Pair(4), Flags(0), null));
            Assert.Throws<ArgumentException>(() => v6.AddSubKey(EdDsaPair(4), Flags(PgpKeyFlags.CanSign), null));

            PgpKeyRingGenerator v4 = NewGenerator(4);
            Assert.Throws<ArgumentException>(() => v4.AddSubKey(X25519Pair(6), Flags(0), null));
        }

        [Test]
        public void EncryptionOnlyPrimaryRefused()
        {
            var mlKem = new MLKem1024X448PrivateKeyParameters(Random);
            var mlKem768 = new MLKem768X25519PrivateKeyParameters(Random);
            var pairs = new[]
            {
                X25519Pair(6),
                new PgpKeyPair(6, PublicKeyAlgorithmTag.MLKem1024_X448, mlKem.GeneratePublicKey(), mlKem,
                    DateTime.UtcNow),
                new PgpKeyPair(6, PublicKeyAlgorithmTag.MLKem768_X25519, mlKem768.GeneratePublicKey(), mlKem768,
                    DateTime.UtcNow),
            };

            foreach (PgpKeyPair pair in pairs)
            {
                Assert.Throws<ArgumentException>(() => new PgpKeyRingGenerator(pair, HashAlgorithmTag.Sha256, null,
                    null, PgpSecretKeyProtection.None, Random), pair.PublicKey.Algorithm.ToString());
            }
        }

        [Test]
        public void HashAlgorithmsForVersion6()
        {
            foreach (var hash in new[]{ HashAlgorithmTag.Sha1, HashAlgorithmTag.MD5, HashAlgorithmTag.RipeMD160 })
            {
                Assert.Throws<ArgumentException>(() => NewGenerator(6, hash: hash), hash.ToString());
            }

            foreach (var hash in new[]
            {
                HashAlgorithmTag.Sha256, HashAlgorithmTag.Sha384, HashAlgorithmTag.Sha512, HashAlgorithmTag.Sha3_256,
                HashAlgorithmTag.Sha3_512,
            })
            {
                Assert.That(NewGenerator(6, hash: hash).GeneratePublicKeyRing().GetPublicKey().Version, Is.EqualTo(6));
            }

            // Ed25519 signatures need a digest of at least 256 bits, in version 4 too
            Assert.Throws<PgpException>(() => NewGenerator(4, hash: HashAlgorithmTag.Sha1));
        }

        [Test]
        public void PreferencesAreCopiedVerbatim()
        {
            PgpKeyRingGenerator generator = NewGenerator(6);
            PgpPublicKey primary = generator.GeneratePublicKeyRing().GetPublicKey();
            PgpSignature direct = primary.GetKeySignatures().Cast<PgpSignature>().Single();
            PgpSignatureSubpacketVector hashed = direct.GetHashedSubPackets();

            Assert.That(hashed.GetKeyFlags(), Is.EqualTo(PgpKeyFlags.CanCertify | PgpKeyFlags.CanSign));
            Assert.That(hashed.GetPreferredSymmetricAlgorithms(),
                Is.EqualTo(new[]{ (int)SymmetricKeyAlgorithmTag.Aes256, (int)SymmetricKeyAlgorithmTag.Aes128 }));
            Assert.That(hashed.GetPreferredHashAlgorithms(), Is.EqualTo(new[]{ (int)HashAlgorithmTag.Sha512 }));
            Assert.That(hashed.GetFeatures().SupportsSeipdV2(), Is.True);
            Assert.That(hashed.GetIssuerFingerprint(), Is.Not.Null);
            Assert.That(hashed.GetIssuerKeyId(), Is.EqualTo(0L));

            // and nothing else is added
            Assert.That(hashed.GetPreferredAeadAlgorithms(), Is.Null.Or.Empty);
        }

        [Test]
        public void EncodingsRoundTrip()
        {
            PgpKeyRingGenerator generator = NewGenerator(6,
                PgpSecretKeyProtection.AeadArgon2(SymmetricKeyAlgorithmTag.Aes256, AeadAlgorithmTag.Ocb,
                    SmallArgon2(), PassPhrase));
            generator.AddUserId("Carol", PgpSignature.PositiveCertification, null, null);
            generator.AddSubKey(X25519Pair(6), Flags(PgpKeyFlags.CanEncryptCommunications), null);
            generator.AddSubKey(EdDsaPair(6), Flags(PgpKeyFlags.CanSign), null);

            byte[] publicEncoding = generator.GeneratePublicKeyRing().GetEncoded();
            byte[] secretEncoding = generator.GenerateSecretKeyRing().GetEncoded();

            Assert.That(new PgpPublicKeyRing(publicEncoding).GetEncoded(), Is.EqualTo(publicEncoding));
            Assert.That(new PgpSecretKeyRing(secretEncoding).GetEncoded(), Is.EqualTo(secretEncoding));
        }

        [Test]
        public void PassPhraseIsWipedAfterGeneration()
        {
            PgpSecretKeyProtection protection = PgpSecretKeyProtection.AeadIterated(SymmetricKeyAlgorithmTag.Aes256,
                AeadAlgorithmTag.Ocb, HashAlgorithmTag.Sha256, 0x60, Arrays.Clone(PassPhrase));

            PgpKeyRingGenerator generator = new PgpKeyRingGenerator(EdDsaPair(6), HashAlgorithmTag.Sha256, null, null,
                protection, Random);
            Assert.That(protection.GetPassPhrase(), Is.EqualTo(PassPhrase));

            generator.AddSubKey(X25519Pair(6), Flags(PgpKeyFlags.CanEncryptCommunications), null);
            generator.GenerateSecretKeyRing();

            Assert.Throws<InvalidOperationException>(() => protection.GetPassPhrase());
            Assert.Throws<InvalidOperationException>(() => generator.AddSubKey(X25519Pair(6), null, null));
            Assert.Throws<InvalidOperationException>(() =>
                generator.AddUserId("late", PgpSignature.PositiveCertification, null, null));

            // the public ring is still available
            Assert.That(generator.GeneratePublicKeyRing().GetPublicKeys().Count(), Is.EqualTo(2));
        }

        // A ring that follows the RFC 9980 7.1 advice, with post-quantum subkeys.
        [Test]
        public void PostQuantumRing()
        {
            var primary = PgpMLDsaEdDsaTest.NewKeyPair(PublicKeyAlgorithmTag.MLDsa65_Ed25519);

            var hashed = new PgpSignatureSubpacketGenerator();
            hashed.SetKeyFlags(false, PgpKeyFlags.CanCertify | PgpKeyFlags.CanSign);
            hashed.SetPreferredSymmetricAlgorithms(false, new[]{ (int)SymmetricKeyAlgorithmTag.Aes256 });
            hashed.SetPreferredAeadCiphersuites(false, new[]
            {
                new PreferredAeadCiphersuites.Combination(SymmetricKeyAlgorithmTag.Aes256, AeadAlgorithmTag.Ocb),
            });
            hashed.SetFeature(false, (byte)(Features.FEATURE_MODIFICATION_DETECTION | Features.FEATURE_SEIPD_V2));

            var generator = new PgpKeyRingGenerator(primary, HashAlgorithmTag.Sha3_256, hashed.Generate(), null,
                PgpSecretKeyProtection.AeadArgon2(SymmetricKeyAlgorithmTag.Aes256, AeadAlgorithmTag.Ocb,
                    SmallArgon2(), PassPhrase), Random);
            generator.AddUserId("pq@example.org", PgpSignature.PositiveCertification, null, null);

            var kem = new MLKem1024X448PrivateKeyParameters(Random);
            generator.AddSubKey(new PgpKeyPair(6, PublicKeyAlgorithmTag.MLKem1024_X448, kem.GeneratePublicKey(), kem,
                DateTime.UtcNow), Flags(PgpKeyFlags.CanEncryptCommunications), null);
            generator.AddSubKey(PgpSlhDsaTest.NewKeyPair(PublicKeyAlgorithmTag.SlhDsa_Shake128f),
                Flags(PgpKeyFlags.CanSign), null);

            var publicRing = new PgpPublicKeyRing(generator.GeneratePublicKeyRing().GetEncoded());
            var secretRing = new PgpSecretKeyRing(generator.GenerateSecretKeyRing().GetEncoded());

            PgpPublicKey[] keys = publicRing.GetPublicKeys().ToArray();
            CheckBinding(keys[0], keys[1], embeddedExpected: false);
            CheckBinding(keys[0], keys[2], embeddedExpected: true);

            // every secret key unlocks with the pass phrase and only with it
            foreach (PgpSecretKey secretKey in secretRing.GetSecretKeys())
            {
                Assert.That(secretKey.ExtractPrivateKeyRaw(PassPhrase), Is.Not.Null);
                Assert.Throws<PgpException>(() => secretKey.ExtractPrivateKeyRaw(Strings.ToUtf8ByteArray("wrong")));
            }

            // and the ring works: sign with the SLH-DSA subkey and encrypt to the ML-KEM subkey
            PgpSecretKey[] secretKeys = secretRing.GetSecretKeys().ToArray();
            byte[] message = Strings.ToUtf8ByteArray("hello post-quantum world");
            byte[] encrypted = PgpV6PkeskTest.EncryptV2(new[]{ keys[1] }, message);
            PgpMLKemX25519Test.Decrypted decrypted = PgpMLKemX25519Test.Decrypt(encrypted,
                secretKeys[1].ExtractPrivateKeyRaw(PassPhrase));
            Assert.That(decrypted.Content, Is.EqualTo(message));
        }

        private static PgpSignature SingleSignature(IEnumerable<PgpSignature> signatures)
        {
            PgpSignature[] array = signatures.ToArray();
            Assert.That(array.Length, Is.EqualTo(1));
            return array[0];
        }

        private static void CheckPostQuantumPreferences(PgpSignature signature, bool aead)
        {
            PgpSignatureSubpacketVector hashed = signature.GetHashedSubPackets();
            Assert.That(hashed.GetPreferredSymmetricAlgorithms(),
                Is.EqualTo(new[]{ (int)SymmetricKeyAlgorithmTag.Aes256, (int)SymmetricKeyAlgorithmTag.Aes128 }));

            PreferredAeadCiphersuites suites = hashed.GetPreferredAeadCiphersuites();
            if (!aead)
            {
                Assert.That(suites, Is.Null);
                return;
            }
            Assert.That(suites.GetRawAlgorithms(), Is.EqualTo(new[]
            {
                new PreferredAeadCiphersuites.Combination(SymmetricKeyAlgorithmTag.Aes256, AeadAlgorithmTag.Ocb),
                new PreferredAeadCiphersuites.Combination(SymmetricKeyAlgorithmTag.Aes128, AeadAlgorithmTag.Ocb),
            }));
        }

        // RFC 9980 7.1: certificates with keys of the RFC 9980 algorithms list AES-256 (and AES-256 with OCB); the
        // generator adds the lists where the caller does not give them
        [Test]
        public void PostQuantumCertificatesListAes256()
        {
            // a post-quantum primary key
            var mlDsa = new PgpKeyRingGenerator(PgpMLDsaEdDsaTest.NewKeyPair(PublicKeyAlgorithmTag.MLDsa65_Ed25519),
                HashAlgorithmTag.Sha256, Flags(PgpKeyFlags.CanCertify | PgpKeyFlags.CanSign), null,
                PgpSecretKeyProtection.None, Random);
            PgpPublicKey primary = mlDsa.GeneratePublicKeyRing().GetPublicKey();
            CheckPostQuantumPreferences(SingleSignature(primary.GetSignaturesOfType(PgpSignature.DirectKey)), true);

            // a classic primary key gets them with its first post-quantum subkey: the direct-key signature is made
            // again, with the same creation time
            PgpKeyRingGenerator generator = new PgpKeyRingGenerator(EdDsaPair(6), HashAlgorithmTag.Sha256,
                Flags(PgpKeyFlags.CanCertify | PgpKeyFlags.CanSign), null, PgpSecretKeyProtection.None, Random);
            PgpSignature before = SingleSignature(generator.GeneratePublicKeyRing().GetPublicKey()
                .GetSignaturesOfType(PgpSignature.DirectKey));
            Assert.That(before.GetHashedSubPackets().GetPreferredSymmetricAlgorithms(), Is.Null);

            generator.AddSubKey(X25519Pair(6), Flags(PgpKeyFlags.CanEncryptCommunications), null);
            var kem = new MLKem768X25519PrivateKeyParameters(Random);
            generator.AddSubKey(new PgpKeyPair(6, PublicKeyAlgorithmTag.MLKem768_X25519, kem.GeneratePublicKey(), kem,
                DateTime.UtcNow), Flags(PgpKeyFlags.CanEncryptCommunications), null);

            var ring = new PgpPublicKeyRing(generator.GeneratePublicKeyRing().GetEncoded());
            PgpSignature after = SingleSignature(ring.GetPublicKey().GetSignaturesOfType(PgpSignature.DirectKey));
            CheckPostQuantumPreferences(after, true);
            Assert.That(after.CreationTime, Is.EqualTo(before.CreationTime));
            after.InitVerify(ring.GetPublicKey());
            Assert.That(after.VerifyCertification(ring.GetPublicKey()), Is.True);
            Assert.That(PgpEncryptionPreferences.Select(new[]{ ring }).SymmetricAlgorithm,
                Is.EqualTo(SymmetricKeyAlgorithmTag.Aes256));

            // lists that the caller gives are kept as they are
            var camellia = new PgpSignatureSubpacketGenerator();
            camellia.SetPreferredSymmetricAlgorithms(false, new[]{ (int)SymmetricKeyAlgorithmTag.Camellia256 });
            camellia.SetPreferredAeadCiphersuites(false, new[]
            {
                new PreferredAeadCiphersuites.Combination(SymmetricKeyAlgorithmTag.Camellia256, AeadAlgorithmTag.Gcm),
            });
            generator = new PgpKeyRingGenerator(EdDsaPair(6), HashAlgorithmTag.Sha256, camellia.Generate(), null,
                PgpSecretKeyProtection.None, Random);
            generator.AddSubKey(new PgpKeyPair(6, PublicKeyAlgorithmTag.MLKem768_X25519, kem.GeneratePublicKey(), kem,
                DateTime.UtcNow), Flags(PgpKeyFlags.CanEncryptCommunications), null);
            PgpSignatureSubpacketVector given = SingleSignature(generator.GeneratePublicKeyRing().GetPublicKey()
                .GetSignaturesOfType(PgpSignature.DirectKey)).GetHashedSubPackets();
            Assert.That(given.GetPreferredSymmetricAlgorithms(),
                Is.EqualTo(new[]{ (int)SymmetricKeyAlgorithmTag.Camellia256 }));
            Assert.That(given.GetPreferredAeadCiphersuites().GetRawAlgorithms().Length, Is.EqualTo(1));

            // a missing AEAD list is added to a given list of ciphers
            generator = NewGenerator(6);
            generator.AddSubKey(new PgpKeyPair(6, PublicKeyAlgorithmTag.MLKem768_X25519, kem.GeneratePublicKey(), kem,
                DateTime.UtcNow), Flags(PgpKeyFlags.CanEncryptCommunications), null);
            CheckPostQuantumPreferences(SingleSignature(generator.GeneratePublicKeyRing().GetPublicKey()
                .GetSignaturesOfType(PgpSignature.DirectKey)), true);

            // and a certificate without post-quantum keys gets nothing
            generator = new PgpKeyRingGenerator(EdDsaPair(6), HashAlgorithmTag.Sha256,
                Flags(PgpKeyFlags.CanCertify | PgpKeyFlags.CanSign), null, PgpSecretKeyProtection.None, Random);
            generator.AddSubKey(X25519Pair(6), Flags(PgpKeyFlags.CanEncryptCommunications), null);
            Assert.That(SingleSignature(generator.GeneratePublicKeyRing().GetPublicKey()
                .GetSignaturesOfType(PgpSignature.DirectKey)).GetHashedSubPackets().GetPreferredSymmetricAlgorithms(),
                Is.Null);
        }

        // The same for the certification of the user ID of a version 4 key made with the classic generator; there are
        // no AEAD ciphersuites without version 2 SEIPD
        [Test]
        public void PostQuantumVersion4CertificatesListAes256()
        {
            var generator = new PgpKeyRingGenerator(PgpSignature.PositiveCertification, PgpMLKemX25519Test
                .NewEdDsaKeyPair(), "v4", SymmetricKeyAlgorithmTag.Null, HashAlgorithmTag.Sha256, new char[0], true,
                Flags(PgpKeyFlags.CanCertify | PgpKeyFlags.CanSign), null, Random);
            generator.AddSubKey(PgpMLKemX25519Test.NewMLKemKeyPair());

            var ring = new PgpPublicKeyRing(generator.GeneratePublicKeyRing().GetEncoded());
            PgpPublicKey primary = ring.GetPublicKey();
            PgpSignature certification = SingleSignature(primary.GetSignaturesForId("v4"));
            CheckPostQuantumPreferences(certification, false);
            Assert.That(certification.HashAlgorithm, Is.EqualTo(HashAlgorithmTag.Sha256));
            certification.InitVerify(primary);
            Assert.That(certification.VerifyCertification("v4", primary), Is.True);
        }

        // RFC 9580 5.2.3.10, 10.1.1: the constructors with a user ID also make the direct-key signature of a version 6
        // key, with the preferences, which is made again for a post-quantum subkey
        [Test]
        public void ConstructorsWithUserIdMakeDirectKeySignaturesForVersion6([Values(false, true)] bool withHash)
        {
            PgpKeyPair primary = EdDsaPair(6);
            PgpKeyRingGenerator generator = withHash
                ? new PgpKeyRingGenerator(PgpSignature.PositiveCertification, primary, "v6",
                    SymmetricKeyAlgorithmTag.Null, HashAlgorithmTag.Sha384, new char[0], true, Preferences(), null,
                    Random)
                : new PgpKeyRingGenerator(PgpSignature.PositiveCertification, primary, "v6",
                    SymmetricKeyAlgorithmTag.Null, new char[0], true, Preferences(), null, Random);
            var kem = new MLKem768X25519PrivateKeyParameters(Random);
            generator.AddSubKey(new PgpKeyPair(6, PublicKeyAlgorithmTag.MLKem768_X25519, kem.GeneratePublicKey(), kem,
                DateTime.UtcNow), Flags(PgpKeyFlags.CanEncryptCommunications), null);

            var ring = new PgpPublicKeyRing(generator.GeneratePublicKeyRing().GetEncoded());
            PgpPublicKey key = ring.GetPublicKey();
            PgpSignature directKey = SingleSignature(key.GetSignaturesOfType(PgpSignature.DirectKey));
            Assert.That(directKey.Version, Is.EqualTo(6));
            Assert.That(directKey.HashAlgorithm,
                Is.EqualTo(withHash ? HashAlgorithmTag.Sha384 : HashAlgorithmTag.Sha256));
            directKey.InitVerify(key);
            Assert.That(directKey.VerifyCertification(key), Is.True);
            CheckPostQuantumPreferences(directKey, true);

            Assert.That(PgpEncryptionPreferences.Select(new[]{ ring }).UseSeipdV2, Is.True);
        }

        [Test]
        public void UserIdCertificationTypes()
        {
            PgpKeyRingGenerator generator = NewGenerator(6);
            foreach (int type in new[]{ 0x10, 0x11, 0x12, 0x13 })
            {
                generator.AddUserId("id " + type, type, null, null);
            }

            foreach (int type in new[]{ 0x00, 0x0F, 0x14, 0x18, 0x1F, 0x20, 0x28 })
            {
                Assert.Throws<ArgumentException>(() => generator.AddUserId("bad", type, null, null), "" + type);
            }
            Assert.Throws<ArgumentNullException>(() => generator.AddUserId((string)null, 0x13, null, null));
            Assert.Throws<ArgumentNullException>(() => generator.AddUserId((byte[])null, 0x13, null, null));

            PgpPublicKey primary = generator.GeneratePublicKeyRing().GetPublicKey();
            Assert.That(primary.GetUserIds().Cast<string>().Count(), Is.EqualTo(4));
            Assert.That(primary.GetSignaturesForId("id 17").Single().SignatureType, Is.EqualTo(0x11));
        }

        [Test]
        public void RawUserId()
        {
            PgpKeyRingGenerator generator = NewGenerator(6);
            byte[] rawId = { 0x41, 0xFF, 0xFE, 0x42 };
            generator.AddUserId(rawId, PgpSignature.PositiveCertification, null, null);

            PgpPublicKey primary = new PgpPublicKeyRing(generator.GeneratePublicKeyRing().GetEncoded()).GetPublicKey();
            Assert.That(primary.GetRawUserIds().Single(), Is.EqualTo(rawId));

            PgpSignature certification = primary.GetSignaturesForId(rawId).Single();
            Assert.That(certification.SignatureType, Is.EqualTo(PgpSignature.PositiveCertification));
        }

        [Test]
        public void AddUserIdNeedsDirectKeyGenerator()
        {
            var classic = new PgpKeyRingGenerator(PgpSignature.PositiveCertification, EdDsaPair(4), "id",
                SymmetricKeyAlgorithmTag.Null, HashAlgorithmTag.Sha256, new char[0], true, null, null, Random);

            Assert.Throws<InvalidOperationException>(() =>
                classic.AddUserId("other", PgpSignature.PositiveCertification, null, null));
        }

        [Test]
        public void GeneratedKeysAreUsable()
        {
            PgpKeyRingGenerator generator = NewGenerator(6);
            generator.AddUserId("Dave", PgpSignature.PositiveCertification, null, null);
            generator.AddSubKey(X25519Pair(6), Flags(PgpKeyFlags.CanEncryptCommunications), null);
            generator.AddSubKey(EdDsaPair(6), Flags(PgpKeyFlags.CanSign), null);

            var publicRing = generator.GeneratePublicKeyRing();
            var secretRing = generator.GenerateSecretKeyRing();
            PgpPublicKey[] publicKeys = publicRing.GetPublicKeys().ToArray();
            PgpSecretKey[] secretKeys = secretRing.GetSecretKeys().ToArray();

            byte[] data = Strings.ToUtf8ByteArray("data");
            var signer = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha512);
            signer.InitSign(PgpSignature.BinaryDocument, secretKeys[2].ExtractPrivateKey(null));
            signer.Update(data);
            PgpSignature signature = signer.Generate();
            signature.InitVerify(publicKeys[2]);
            signature.Update(data);
            Assert.That(signature.Verify(), Is.True);

            byte[] encrypted = PgpV6PkeskTest.EncryptV2(new[]{ publicKeys[1] }, data);
            Assert.That(PgpMLKemX25519Test.Decrypt(encrypted, secretKeys[1].ExtractPrivateKey(null)).Content,
                Is.EqualTo(data));
        }
    }
}
