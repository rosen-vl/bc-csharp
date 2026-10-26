using System;
using System.IO;
using System.Linq;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    /// <summary>Tests for the protection of version 6 secret keys (RFC 9580 5.5.3).</summary>
    [TestFixture]
    public class PgpV6SecretKeyProtectionTest
    {
        private static readonly SecureRandom Random = new SecureRandom();

        // the pass phrase of the RFC 9580 A.5 key
        private static readonly byte[] Rfc9580PassPhrase = Strings.ToUtf8ByteArray("correct horse battery staple");

        private static readonly byte[] PassPhrase = Strings.ToUtf8ByteArray("a new pass phrase");

        // Argon2 parameters that are cheap enough for tests
        private static S2k.Argon2Params SmallArgon2() => new S2k.Argon2Params(1, 1, 10, Random);

        private static PgpSecretKeyRing UnprotectedRing() =>
            new PgpSecretKeyRing(PgpV6TestUtilities.LoadRfc9580("a4-v6-secret-key.asc"));

        private static PgpSecretKeyRing LockedRing() =>
            new PgpSecretKeyRing(PgpV6TestUtilities.LoadRfc9580("a5-v6-locked-secret-key.asc"));

        // The keys of RFC 9580 A.4 with AEAD protection and cheap Argon2 parameters (the RFC 9580 A.5 key takes
        // seconds to unlock)
        private static PgpSecretKeyRing SmallLockedRing() => Protect(UnprotectedRing(), null,
            () => PgpSecretKeyProtection.AeadArgon2(SymmetricKeyAlgorithmTag.Aes256, AeadAlgorithmTag.Ocb,
                SmallArgon2(), PassPhrase));

        /// <summary>Rebuild a ring with new versions of its secret keys.</summary>
        private static PgpSecretKeyRing Protect(PgpSecretKeyRing ring, byte[] oldPassPhrase,
            Func<PgpSecretKeyProtection> protection)
        {
            PgpSecretKeyRing result = ring;
            foreach (PgpSecretKey key in ring.GetSecretKeys())
            {
                PgpSecretKey copy = PgpSecretKey.CopyWithNewProtection(key, oldPassPhrase, protection(), Random);
                result = PgpSecretKeyRing.InsertSecretKey(result, copy);
            }
            return result;
        }

        private static PgpSecretKeyRing Unprotect(PgpSecretKeyRing ring, byte[] passPhrase) =>
            Protect(ring, passPhrase, () => PgpSecretKeyProtection.None);

        private static PgpKeyPair Ed25519Pair()
        {
            var generator = new Ed25519KeyPairGenerator();
            generator.Init(new Ed25519KeyGenerationParameters(Random));
            return new PgpKeyPair(6, PublicKeyAlgorithmTag.Ed25519, generator.GenerateKeyPair(), DateTime.UtcNow);
        }

        [Test]
        public void UnprotectedVersion6KeyHasNoChecksum()
        {
            foreach (PgpSecretKey key in UnprotectedRing().GetSecretKeys())
            {
                Assert.That(key.S2kUsage, Is.EqualTo(SecretKeyPacket.UsageNone));
                Assert.That(key.PublicKey.Version, Is.EqualTo(6));
            }

            // protecting a key with nothing writes the same packets, i.e. no checksum is appended
            PgpSecretKeyRing again = Unprotect(UnprotectedRing(), null);
            Assert.That(again.GetEncoded(), Is.EqualTo(PgpV6TestUtilities.LoadRfc9580("a4-v6-secret-key.asc")));
        }

        // RFC 9580 A.5 unlocks to A.4.
        [Test]
        public void Rfc9580LockedKeyEqualsUnprotectedKey()
        {
            PgpSecretKeyRing locked = LockedRing();
            foreach (PgpSecretKey key in locked.GetSecretKeys())
            {
                Assert.That(key.S2kUsage, Is.EqualTo(SecretKeyPacket.UsageAead));
                Assert.That(key.S2k.Type, Is.EqualTo(S2k.Argon2));
                Assert.That(key.KeyEncryptionAlgorithm, Is.EqualTo(SymmetricKeyAlgorithmTag.Aes256));
            }

            // The Argon2 parameters of the vector need 2 GiB of memory
            PgpSecretKeyRing unlocked;
            try
            {
                unlocked = Unprotect(locked, Rfc9580PassPhrase);
            }
            catch (OutOfMemoryException)
            {
                Assert.Ignore("not enough memory for the Argon2 parameters of the RFC 9580 A.5 key");
                return;
            }
            Assert.That(unlocked.GetEncoded(), Is.EqualTo(PgpV6TestUtilities.LoadRfc9580("a4-v6-secret-key.asc")));
        }

        [Test]
        public void AeadProtectionWithArgon2AndIteratedS2k()
        {
            foreach (var aead in new[]{ AeadAlgorithmTag.Eax, AeadAlgorithmTag.Ocb, AeadAlgorithmTag.Gcm })
            {
                PgpSecretKeyRing argon2 = Protect(UnprotectedRing(), null,
                    () => PgpSecretKeyProtection.AeadArgon2(SymmetricKeyAlgorithmTag.Aes256, aead, SmallArgon2(),
                        PassPhrase));

                foreach (PgpSecretKey key in argon2.GetSecretKeys())
                {
                    Assert.That(key.S2kUsage, Is.EqualTo(SecretKeyPacket.UsageAead));
                    Assert.That(key.S2k.Type, Is.EqualTo(S2k.Argon2));
                }
                // each key gets its own salt
                var salts = argon2.GetSecretKeys().Select(k => k.S2k.Argon2Config.GetSalt()).ToArray();
                Assert.That(salts[0], Is.Not.EqualTo(salts[1]));

                Assert.That(Unprotect(argon2, PassPhrase).GetEncoded(),
                    Is.EqualTo(PgpV6TestUtilities.LoadRfc9580("a4-v6-secret-key.asc")));

                // and it survives a round trip through the encoding
                var reloaded = new PgpSecretKeyRing(argon2.GetEncoded());
                Assert.That(Unprotect(reloaded, PassPhrase).GetEncoded(),
                    Is.EqualTo(PgpV6TestUtilities.LoadRfc9580("a4-v6-secret-key.asc")));

                PgpSecretKeyRing iterated = Protect(UnprotectedRing(), null,
                    () => PgpSecretKeyProtection.AeadIterated(SymmetricKeyAlgorithmTag.Aes128, aead,
                        HashAlgorithmTag.Sha256, 0x60, PassPhrase));
                foreach (PgpSecretKey key in iterated.GetSecretKeys())
                {
                    Assert.That(key.S2kUsage, Is.EqualTo(SecretKeyPacket.UsageAead));
                    Assert.That(key.S2k.Type, Is.EqualTo(S2k.SaltedAndIterated));
                }
                Assert.That(Unprotect(iterated, PassPhrase).GetEncoded(),
                    Is.EqualTo(PgpV6TestUtilities.LoadRfc9580("a4-v6-secret-key.asc")));
            }
        }

        [Test]
        public void Version6KeysCanUseCfbWithShaOneCheck()
        {
            PgpSecretKeyRing cfb = Protect(UnprotectedRing(), null,
                () => PgpSecretKeyProtection.Cfb(SymmetricKeyAlgorithmTag.Aes256, HashAlgorithmTag.Sha256, 0x60,
                    PassPhrase));

            foreach (PgpSecretKey key in cfb.GetSecretKeys())
            {
                Assert.That(key.S2kUsage, Is.EqualTo(SecretKeyPacket.UsageSha1));
            }
            Assert.That(Unprotect(cfb, PassPhrase).GetEncoded(),
                Is.EqualTo(PgpV6TestUtilities.LoadRfc9580("a4-v6-secret-key.asc")));
        }

        // RFC 9580 3.7.2 and 13.7: version 6 keys get AEAD protection with Argon2 where the cipher allows it
        [Test]
        public void CopyWithNewPasswordUsesAeadForVersion6()
        {
            char[] password = "secret".ToCharArray();
            PgpSecretKey key = UnprotectedRing().GetSecretKey();

            PgpSecretKey protectedKey = PgpSecretKey.CopyWithNewPassword(key, new char[0], password,
                SymmetricKeyAlgorithmTag.Aes128, Random);
            Assert.That(protectedKey.S2kUsage, Is.EqualTo(SecretKeyPacket.UsageAead));
            Assert.That(protectedKey.S2k.Type, Is.EqualTo(S2k.Argon2));
            Assert.That(protectedKey.KeyEncryptionAlgorithm, Is.EqualTo(SymmetricKeyAlgorithmTag.Aes128));

            PgpSecretKey back = PgpSecretKey.CopyWithNewPassword(protectedKey, "secret".ToCharArray(), new char[0],
                SymmetricKeyAlgorithmTag.Null, Random);
            Assert.That(back.S2kUsage, Is.EqualTo(SecretKeyPacket.UsageNone));
            Assert.That(back.GetEncoded(), Is.EqualTo(key.GetEncoded()));

            // a cipher without AEAD modes falls back to CFB, without the checksum form
            PgpSecretKey blowfish = PgpSecretKey.CopyWithNewPassword(key, new char[0], password,
                SymmetricKeyAlgorithmTag.Blowfish, Random);
            Assert.That(blowfish.S2kUsage, Is.EqualTo(SecretKeyPacket.UsageSha1));
            Assert.That(blowfish.S2k.HashAlgorithm, Is.EqualTo(HashAlgorithmTag.Sha256));
            Assert.That(blowfish.ExtractPrivateKey(password), Is.Not.Null);
        }

        [Test]
        public void LegacyConstructorsUseAeadForVersion6()
        {
            var key = new PgpSecretKey(PgpSignature.PositiveCertification, Ed25519Pair(), "legacy",
                SymmetricKeyAlgorithmTag.Aes256, HashAlgorithmTag.Sha256, "secret".ToCharArray(), true, null, null,
                Random);

            var reparsed = new PgpSecretKeyRing(key.GetEncoded()).GetSecretKey();
            Assert.That(reparsed.S2kUsage, Is.EqualTo(SecretKeyPacket.UsageAead));
            Assert.That(reparsed.S2k.Type, Is.EqualTo(S2k.Argon2));
            Assert.That(reparsed.ExtractPrivateKey("secret".ToCharArray()), Is.Not.Null);
            Assert.Throws<PgpException>(() => reparsed.ExtractPrivateKey("wrong".ToCharArray()));

            // RFC 9580 5.2.3.10: a version 6 key is not used without a direct-key signature
            PgpSignature directKey = reparsed.PublicKey.GetSignaturesOfType(PgpSignature.DirectKey).Single();
            directKey.InitVerify(reparsed.PublicKey);
            Assert.That(directKey.VerifyCertification(reparsed.PublicKey), Is.True);
        }

        // RFC 9580 5.5.3: AEAD protection is not limited to version 6 keys
        [Test]
        public void Version4KeysCanUseAead()
        {
            PgpSecretKeyRing ring = PgpMLKemX25519Test.GenerateRing("v4", null, out _);
            foreach (PgpSecretKey key in ring.GetSecretKeys())
            {
                PgpSecretKey protectedKey = PgpSecretKey.CopyWithNewProtection(key, null,
                    PgpSecretKeyProtection.AeadArgon2(SymmetricKeyAlgorithmTag.Aes256, AeadAlgorithmTag.Ocb,
                        SmallArgon2(), PassPhrase), Random);
                Assert.That(protectedKey.PublicKey.Version, Is.EqualTo(4));
                Assert.That(protectedKey.S2kUsage, Is.EqualTo(SecretKeyPacket.UsageAead));

                PgpSecretKey reparsed = new PgpSecretKeyRing(PgpSecretKeyRing.InsertSecretKey(ring, protectedKey)
                    .GetEncoded()).GetSecretKey(protectedKey.KeyId);
                Assert.That(reparsed.S2kUsage, Is.EqualTo(SecretKeyPacket.UsageAead));
                Assert.That(reparsed.ExtractPrivateKeyRaw(PassPhrase).Key.GetType(),
                    Is.EqualTo(key.ExtractPrivateKey(null).Key.GetType()));
                Assert.Throws<PgpException>(() => reparsed.ExtractPrivateKeyRaw(Strings.ToUtf8ByteArray("wrong")));
            }
        }

        // RFC 9580 9.5: no new S2K with MD5, SHA-1 or RIPEMD-160, also for version 4 keys
        [Test]
        public void LegacyConstructorsUseSha256S2kForVersion4([Values(false, true)] bool useSha1)
        {
            var key = new PgpSecretKey(PgpSignature.PositiveCertification, PgpMLKemX25519Test.NewEcdsaKeyPair(),
                "legacy", SymmetricKeyAlgorithmTag.Aes256, HashAlgorithmTag.Sha256, "secret".ToCharArray(), useSha1,
                null, null, Random);

            var reparsed = new PgpSecretKeyRing(key.GetEncoded()).GetSecretKey();
            Assert.That(reparsed.PublicKey.Version, Is.EqualTo(4));
            // RFC 9580 3.7.2.1: never the checksum form (usage 255), whatever useSha1 says
            Assert.That(reparsed.S2kUsage, Is.EqualTo(SecretKeyPacket.UsageSha1));
            Assert.That(reparsed.S2k.HashAlgorithm, Is.EqualTo(HashAlgorithmTag.Sha256));
            Assert.That(reparsed.ExtractPrivateKey("secret".ToCharArray()), Is.Not.Null);
        }

        [Test]
        public void CopyWithNewPasswordUsesSha256S2kForVersion4()
        {
            // a version 4 key with a SHA-1 S2K, which can still be unlocked (RFC 9580 9.5)
            PgpSecretKey key;
            using (Stream input = SimpleTest.GetTestDataAsStream("openpgp.dsa.keys.DSA-2048-224.sec"))
            {
                key = new PgpSecretKeyRing(input).GetSecretKey();
            }
            Assert.That(key.S2k.HashAlgorithm, Is.EqualTo(HashAlgorithmTag.Sha1));

            PgpSecretKey copy = PgpSecretKey.CopyWithNewPassword(key, "test".ToCharArray(), "new".ToCharArray(),
                SymmetricKeyAlgorithmTag.Aes256, Random);
            Assert.That(copy.S2kUsage, Is.EqualTo(SecretKeyPacket.UsageSha1));
            Assert.That(copy.S2k.HashAlgorithm, Is.EqualTo(HashAlgorithmTag.Sha256));
            Assert.That(copy.ExtractPrivateKey("new".ToCharArray()), Is.Not.Null);

            // and an unprotected one
            PgpSecretKey unprotected = PgpMLKemX25519Test.GenerateRing("v4", null, out _).GetSecretKey();
            copy = PgpSecretKey.CopyWithNewPassword(unprotected, null, "new".ToCharArray(),
                SymmetricKeyAlgorithmTag.Aes256, Random);
            Assert.That(copy.S2kUsage, Is.EqualTo(SecretKeyPacket.UsageSha1));
            Assert.That(copy.S2k.HashAlgorithm, Is.EqualTo(HashAlgorithmTag.Sha256));
            Assert.That(copy.ExtractPrivateKey("new".ToCharArray()), Is.Not.Null);
        }

        // A copy of a version 4 key protected with the checksum form (usage 255), which RFC 9580 3.7.2.1 only allows
        // to read
        private static PgpSecretKey WithMalleableCfb(PgpSecretKey unprotected, char[] passPhrase)
        {
            var packet = (SecretKeyPacket)BcpgInputStream.Wrap(new MemoryStream(unprotected.GetEncoded(), false))
                .ReadPacket();

            S2k s2k = S2k.GenerateSaltedAndIterated(Random, HashAlgorithmTag.Sha256, 0x60);
            KeyParameter key = PgpUtilities.DoMakeKeyFromPassPhrase(SymmetricKeyAlgorithmTag.Aes256, s2k,
                Strings.ToUtf8ByteArray(passPhrase), clearPassPhrase: true);
            byte[] iv = SecureRandom.GetNextBytes(Random, 16);
            var cipher = CipherUtilities.GetCipher("AES/CFB/NoPadding");
            cipher.Init(true, new ParametersWithIV(key, iv));

            // the key material and its 2-octet checksum
            byte[] encrypted = cipher.DoFinal(packet.GetSecretKeyData());
            return new PgpSecretKey(new SecretKeyPacket(packet.PublicKeyPacket, SymmetricKeyAlgorithmTag.Aes256,
                SecretKeyPacket.UsageChecksum, s2k, iv, encrypted), unprotected.PublicKey);
        }

        // RFC 9580 3.7.2.1: the checksum form (usage 255) is read, but CopyWithNewPassword makes usage 254 of it
        [Test]
        public void CopyWithNewPasswordNeverGeneratesUsage255()
        {
            char[] password = "secret".ToCharArray();
            PgpSecretKey unprotected = PgpMLKemX25519Test.GenerateRing("v4", null, out _).GetSecretKey();
            PgpSecretKey malleable = WithMalleableCfb(unprotected, password);
            Assert.That(malleable.S2kUsage, Is.EqualTo(SecretKeyPacket.UsageChecksum));
            Assert.That(malleable.ExtractPrivateKey(password), Is.Not.Null);

            foreach (var (key, oldPassword) in new[]{ (unprotected, (char[])null), (malleable, password) })
            {
                PgpSecretKey copy = PgpSecretKey.CopyWithNewPassword(key, oldPassword, "new".ToCharArray(),
                    SymmetricKeyAlgorithmTag.Aes256, Random);
                PgpSecretKey reparsed = new PgpSecretKeyRing(copy.GetEncoded()).GetSecretKey();
                Assert.That(reparsed.S2kUsage, Is.EqualTo(SecretKeyPacket.UsageSha1));
                Assert.That(reparsed.ExtractPrivateKey("new".ToCharArray()), Is.Not.Null);

                PgpSecretKey back = PgpSecretKey.CopyWithNewPassword(reparsed, "new".ToCharArray(), null,
                    SymmetricKeyAlgorithmTag.Null, Random);
                Assert.That(back.GetEncoded(), Is.EqualTo(unprotected.GetEncoded()));
            }
        }

        // AEAD protected version 4 keys have neither the SHA-1 hash nor the checksum of the other forms
        [Test]
        public void AeadProtectedVersion4KeysCanBeCopied()
        {
            PgpSecretKey unprotected = PgpMLKemX25519Test.GenerateRing("v4", null, out _).GetSecretKey();
            PgpSecretKey aead = PgpSecretKey.CopyWithNewProtection(unprotected, null,
                PgpSecretKeyProtection.AeadArgon2(SymmetricKeyAlgorithmTag.Aes256, AeadAlgorithmTag.Ocb, SmallArgon2(),
                    PassPhrase), Random);
            Assert.That(aead.S2kUsage, Is.EqualTo(SecretKeyPacket.UsageAead));

            // unprotected again, with the checksum of version 4 keys
            PgpSecretKey back = PgpSecretKey.CopyWithNewPasswordRaw(aead, PassPhrase, null,
                SymmetricKeyAlgorithmTag.Null, Random);
            Assert.That(back.GetEncoded(), Is.EqualTo(unprotected.GetEncoded()));

            byte[] newPassPhrase = Strings.ToUtf8ByteArray("new");
            PgpSecretKey cfb = PgpSecretKey.CopyWithNewPasswordRaw(aead, PassPhrase, newPassPhrase,
                SymmetricKeyAlgorithmTag.Aes128, Random);
            PgpSecretKey reparsed = new PgpSecretKeyRing(cfb.GetEncoded()).GetSecretKey();
            Assert.That(reparsed.S2kUsage, Is.EqualTo(SecretKeyPacket.UsageSha1));
            Assert.That(reparsed.ExtractPrivateKeyRaw(newPassPhrase).Key.GetType(),
                Is.EqualTo(unprotected.ExtractPrivateKey(null).Key.GetType()));
            Assert.That(PgpSecretKey.CopyWithNewPasswordRaw(reparsed, newPassPhrase, null,
                SymmetricKeyAlgorithmTag.Null, Random).GetEncoded(), Is.EqualTo(unprotected.GetEncoded()));
        }

        [Test]
        public void CorruptedAeadProtectedKeyIsRejected()
        {
            byte[] encoding = SmallLockedRing().GetEncoded();

            // flip an octet of the encrypted key data of the primary key
            var packets = PgpUnsupportedVersionTest.SplitPackets(encoding);
            byte[] keyPacket = packets[0];
            foreach (int fromEnd in new[]{ 1, 20 })
            {
                byte[] modifiedPacket = Arrays.Clone(keyPacket);
                modifiedPacket[modifiedPacket.Length - fromEnd] ^= 0x01;
                byte[] modified = Arrays.Concatenate(modifiedPacket,
                    Arrays.ConcatenateAll(packets.Skip(1).ToArray()));

                PgpSecretKey key = new PgpSecretKeyRing(modified).GetSecretKey();
                Assert.Throws<PgpException>(() => PgpSecretKey.CopyWithNewProtection(key, PassPhrase,
                    PgpSecretKeyProtection.None, Random));
            }

            // an unmodified key works
            PgpSecretKey intact = new PgpSecretKeyRing(encoding).GetSecretKey();
            Assert.DoesNotThrow(() => PgpSecretKey.CopyWithNewProtection(intact, PassPhrase,
                PgpSecretKeyProtection.None, Random));
        }

        [Test]
        public void AeadProtectedKeyIsBoundToItsPublicKey()
        {
            byte[] encoding = SmallLockedRing().GetEncoded();
            var packets = PgpUnsupportedVersionTest.SplitPackets(encoding);

            // change the creation time of the primary key: the tag no longer verifies
            byte[] keyPacket = Arrays.Clone(packets[0]);
            keyPacket[2 + 4] ^= 0x01;
            byte[] modified = Arrays.Concatenate(keyPacket, Arrays.ConcatenateAll(packets.Skip(1).ToArray()));

            PgpSecretKey key = new PgpSecretKeyRing(modified).GetSecretKey();
            Assert.Throws<PgpException>(() => PgpSecretKey.CopyWithNewProtection(key, PassPhrase,
                PgpSecretKeyProtection.None, Random));
        }

        [Test]
        public void WrongPassPhraseIsRejected()
        {
            PgpSecretKey key = SmallLockedRing().GetSecretKey();

            Assert.Throws<PgpException>(() => PgpSecretKey.CopyWithNewProtection(key,
                Strings.ToUtf8ByteArray("wrong"), PgpSecretKeyProtection.None, Random));
        }

        [Test]
        public void ProtectionChainsAreLossless()
        {
            PgpSecretKeyRing ring = UnprotectedRing();
            ring = Protect(ring, null, () => PgpSecretKeyProtection.Cfb(SymmetricKeyAlgorithmTag.Camellia192,
                HashAlgorithmTag.Sha512, 0x80, Strings.ToUtf8ByteArray("one")));
            ring = Protect(ring, Strings.ToUtf8ByteArray("one"), () => PgpSecretKeyProtection.AeadArgon2(
                SymmetricKeyAlgorithmTag.Twofish, AeadAlgorithmTag.Gcm, SmallArgon2(), Strings.ToUtf8ByteArray("two")));
            ring = Protect(ring, Strings.ToUtf8ByteArray("two"), () => PgpSecretKeyProtection.AeadIterated(
                SymmetricKeyAlgorithmTag.Camellia256, AeadAlgorithmTag.Eax, HashAlgorithmTag.Sha3_256, 0x70,
                Strings.ToUtf8ByteArray("three")));
            ring = Unprotect(ring, Strings.ToUtf8ByteArray("three"));

            Assert.That(ring.GetEncoded(), Is.EqualTo(PgpV6TestUtilities.LoadRfc9580("a4-v6-secret-key.asc")));
        }

        private static readonly SymmetricKeyAlgorithmTag[] DecryptOnlyCiphers =
        {
            SymmetricKeyAlgorithmTag.Idea, SymmetricKeyAlgorithmTag.TripleDes, SymmetricKeyAlgorithmTag.Cast5,
        };

        // RFC 9580 9.3: version 6 keys are not protected with IDEA, TripleDES or CAST5; version 4 keys still are,
        // for compatibility
        [Test]
        public void DecryptOnlyCiphersAreRefusedForVersion6Keys()
        {
            PgpSecretKey key = UnprotectedRing().GetSecretKey();
            PgpSecretKey v4Key = PgpMLKemX25519Test.GenerateRing("v4", null, out _).GetSecretKey();
            foreach (var cipher in DecryptOnlyCiphers)
            {
                Assert.Throws<ArgumentException>(() => PgpSecretKey.CopyWithNewPassword(key, new char[0],
                    "secret".ToCharArray(), cipher, Random), cipher.ToString());
                Assert.Throws<PgpException>(() => new PgpSecretKey(PgpSignature.PositiveCertification,
                    Ed25519Pair(), "legacy", cipher, HashAlgorithmTag.Sha256, "secret".ToCharArray(), true, null, null,
                    Random), cipher.ToString());

                PgpSecretKey v4Copy = PgpSecretKey.CopyWithNewPassword(v4Key, null, "secret".ToCharArray(), cipher,
                    Random);
                Assert.That(v4Copy.KeyEncryptionAlgorithm, Is.EqualTo(cipher));
            }
        }

        [Test]
        public void ProtectionFactoriesValidateTheirArguments()
        {
            // RFC 9580 9.3: IDEA, TripleDES and CAST5 are only for decryption
            foreach (var cipher in DecryptOnlyCiphers)
            {
                Assert.Throws<ArgumentException>(() => PgpSecretKeyProtection.Cfb(cipher, HashAlgorithmTag.Sha256,
                    0x60, PassPhrase), cipher.ToString());
            }

            Assert.Throws<ArgumentException>(() => PgpSecretKeyProtection.AeadArgon2(SymmetricKeyAlgorithmTag.Cast5,
                AeadAlgorithmTag.Ocb, SmallArgon2(), PassPhrase));
            Assert.Throws<ArgumentException>(() => PgpSecretKeyProtection.AeadArgon2(SymmetricKeyAlgorithmTag.Aes128,
                (AeadAlgorithmTag)77, SmallArgon2(), PassPhrase));
            Assert.Throws<ArgumentNullException>(() => PgpSecretKeyProtection.AeadArgon2(
                SymmetricKeyAlgorithmTag.Aes128, AeadAlgorithmTag.Ocb, null, PassPhrase));
            Assert.Throws<ArgumentNullException>(() => PgpSecretKeyProtection.AeadArgon2(
                SymmetricKeyAlgorithmTag.Aes128, AeadAlgorithmTag.Ocb, SmallArgon2(), null));

            foreach (var hash in new[]{ HashAlgorithmTag.MD5, HashAlgorithmTag.Sha1, HashAlgorithmTag.RipeMD160 })
            {
                Assert.Throws<ArgumentException>(() => PgpSecretKeyProtection.AeadIterated(
                    SymmetricKeyAlgorithmTag.Aes128, AeadAlgorithmTag.Ocb, hash, 0x60, PassPhrase), hash.ToString());

                // RFC 9580 9.5: whatever the version of the key
                Assert.Throws<ArgumentException>(() => PgpSecretKeyProtection.Cfb(SymmetricKeyAlgorithmTag.Aes128,
                    hash, 0x60, PassPhrase), hash.ToString());
            }

            Assert.Throws<ArgumentOutOfRangeException>(() => PgpSecretKeyProtection.Cfb(
                SymmetricKeyAlgorithmTag.Aes128, HashAlgorithmTag.Sha256, 256, PassPhrase));
        }

        [Test]
        public void ProtectionClearsItsPassPhrase()
        {
            byte[] passPhrase = Strings.ToUtf8ByteArray("clear me");
            var protection = PgpSecretKeyProtection.AeadArgon2(SymmetricKeyAlgorithmTag.Aes128, AeadAlgorithmTag.Ocb,
                SmallArgon2(), passPhrase);

            // the factory copies the pass phrase
            Assert.That(passPhrase, Is.EqualTo(Strings.ToUtf8ByteArray("clear me")));

            PgpSecretKey.CopyWithNewProtection(UnprotectedRing().GetSecretKey(), null, protection, Random);

            Assert.Throws<InvalidOperationException>(() => protection.GetPassPhrase());
        }

        // A wiped protection consists of zeroes: using it again would protect keys with a pass phrase of zero octets.
        [Test]
        public void UsedProtectionCannotBeReused()
        {
            PgpSecretKeyProtection Aead() => PgpSecretKeyProtection.AeadArgon2(SymmetricKeyAlgorithmTag.Aes256,
                AeadAlgorithmTag.Ocb, SmallArgon2(), PassPhrase);

            // copies of keys
            PgpSecretKey[] keys = UnprotectedRing().GetSecretKeys().ToArray();
            PgpSecretKeyProtection protection = Aead();
            PgpSecretKey first = PgpSecretKey.CopyWithNewProtection(keys[0], null, protection, Random);
            Assert.Throws<InvalidOperationException>(
                () => PgpSecretKey.CopyWithNewProtection(keys[1], null, protection, Random));
            Assert.That(first.ExtractPrivateKeyRaw(PassPhrase), Is.Not.Null);
            Assert.Throws<PgpException>(() => first.ExtractPrivateKeyRaw(new byte[PassPhrase.Length]));

            // a generator that has finished
            protection = Aead();
            var generator = new PgpKeyRingGenerator(Ed25519Pair(), HashAlgorithmTag.Sha256, null, null, protection,
                Random);
            generator.GenerateSecretKeyRing();
            Assert.Throws<InvalidOperationException>(() => new PgpKeyRingGenerator(Ed25519Pair(),
                HashAlgorithmTag.Sha256, null, null, protection, Random));

            // two generators that share a protection: the second one cannot add keys after the first has finished
            protection = Aead();
            var one = new PgpKeyRingGenerator(Ed25519Pair(), HashAlgorithmTag.Sha256, null, null, protection, Random);
            var two = new PgpKeyRingGenerator(Ed25519Pair(), HashAlgorithmTag.Sha256, null, null, protection, Random);
            one.GenerateSecretKeyRing();
            var mlKem = new MLKem768X25519PrivateKeyParameters(Random);
            Assert.Throws<InvalidOperationException>(() => two.AddSubKey(new PgpKeyPair(6,
                PublicKeyAlgorithmTag.MLKem768_X25519, mlKem.GeneratePublicKey(), mlKem, DateTime.UtcNow), null, null));
            PgpSecretKey primary = two.GenerateSecretKeyRing().GetSecretKey();
            Assert.That(primary.ExtractPrivateKeyRaw(PassPhrase), Is.Not.Null);

            // the protection without a pass phrase can be used any number of times
            foreach (PgpSecretKey key in keys)
            {
                Assert.That(PgpSecretKey.CopyWithNewProtection(key, null, PgpSecretKeyProtection.None, Random)
                    .S2kUsage, Is.EqualTo(SecretKeyPacket.UsageNone));
            }
        }

        // The body of a version 6 secret key packet with the given usage octet and conditional parameters
        private static byte[] V6SecretKeyBody(int usage, byte[] conditional, byte[] secretData)
        {
            byte[] publicBody = Arrays.CopyOfRange(PgpUnsupportedVersionTest.SplitPackets(
                PgpV6TestUtilities.LoadRfc9580("a3-v6-certificate.asc"))[0], 2, 2 + 42);

            var body = new MemoryStream();
            body.Write(publicBody, 0, publicBody.Length);
            body.WriteByte((byte)usage);
            body.WriteByte((byte)conditional.Length);
            body.Write(conditional, 0, conditional.Length);
            body.Write(secretData, 0, secretData.Length);
            return body.ToArray();
        }

        private static PgpSecretKey ParseSecretKey(byte[] body) => new PgpSecretKeyRing(
            PgpV6TestUtilities.NewFormatPacket(PacketTag.SecretKey, body)).GetSecretKey();

        [Test]
        public void Usage255IsRefusedForVersion6Keys()
        {
            // symmetric algorithm, iterated S2K, IV
            byte[] conditional = Arrays.ConcatenateAll(new byte[]{ (byte)SymmetricKeyAlgorithmTag.Aes128 },
                new byte[]{ 3, (byte)HashAlgorithmTag.Sha256, 1, 2, 3, 4, 5, 6, 7, 8, 0x60 }, new byte[16]);

            PgpSecretKey key = ParseSecretKey(V6SecretKeyBody(SecretKeyPacket.UsageChecksum, conditional,
                new byte[32 + 2]));

            var e = Assert.Throws<PgpException>(() => key.ExtractPrivateKey("password".ToCharArray()));
            Assert.That(e.Message, Does.Contain("version 6"));
        }

        /// <summary>RFC 9580 9.5: deprecated S2K hashes are refused before any derivation for version 6 keys.</summary>
        [Test]
        public void DeprecatedS2kHashIsRefusedForVersion6Keys()
        {
            foreach (var hash in new[]{ HashAlgorithmTag.MD5, HashAlgorithmTag.Sha1, HashAlgorithmTag.RipeMD160 })
            {
                // symmetric algorithm, S2K length, iterated S2K, IV
                byte[] s2k = { 3, (byte)hash, 1, 2, 3, 4, 5, 6, 7, 8, 0x60 };
                byte[] conditional = Arrays.ConcatenateAll(new byte[]{ (byte)SymmetricKeyAlgorithmTag.Aes128,
                    (byte)s2k.Length }, s2k, new byte[16]);

                PgpSecretKey key = ParseSecretKey(V6SecretKeyBody(SecretKeyPacket.UsageSha1, conditional,
                    new byte[32 + 20]));

                var e = Assert.Throws<PgpException>(() => key.ExtractPrivateKey("password".ToCharArray()),
                    hash.ToString());
                Assert.That(e.Message, Does.Contain("not allowed"));
            }
        }
    }
}
