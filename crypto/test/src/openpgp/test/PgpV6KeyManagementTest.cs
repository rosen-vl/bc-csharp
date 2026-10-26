using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

using NUnit.Framework;

using Org.BouncyCastle.Bcpg.Sig;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    /// <summary>
    /// Key management operations on version 6 certificates and keys: extraction of the public part, third-party
    /// certifications across key versions (checked against an independent computation of the hashed data),
    /// revocations, adding and removing keys and signatures, merging, bundles and key lookups by the v6 key ID, and
    /// pass phrase encodings of the new protection schemes.
    /// </summary>
    [TestFixture]
    public class PgpV6KeyManagementTest
    {
        private static readonly SecureRandom Random = new SecureRandom();

        private static AsymmetricCipherKeyPair NewEd25519()
        {
            var generator = new Ed25519KeyPairGenerator();
            generator.Init(new Ed25519KeyGenerationParameters(Random));
            return generator.GenerateKeyPair();
        }

        private static PgpSignatureSubpacketVector Hashed(int keyFlags, long keyExpirationSeconds = 0)
        {
            var generator = new PgpSignatureSubpacketGenerator();
            generator.SetKeyFlags(false, keyFlags);
            if (keyExpirationSeconds != 0)
            {
                generator.SetKeyExpirationTime(true, keyExpirationSeconds);
            }
            generator.SetFeature(false, (byte)(Features.FEATURE_MODIFICATION_DETECTION | Features.FEATURE_SEIPD_V2));
            return generator.Generate();
        }

        /// <summary>A version 6 ring: Ed25519 primary, a user ID, an ML-KEM-768+X25519 and an Ed25519 subkey.</summary>
        private static PgpSecretKeyRing NewV6Ring(string userId, PgpSecretKeyProtection protection = null,
            long subkeyExpiration = 0)
        {
            var primary = new PgpKeyPair(6, PublicKeyAlgorithmTag.Ed25519, NewEd25519(),
                DateTime.UtcNow.AddMinutes(-5));
            var generator = new PgpKeyRingGenerator(primary, HashAlgorithmTag.Sha512,
                Hashed(PgpKeyFlags.CanCertify | PgpKeyFlags.CanSign), null, protection ?? PgpSecretKeyProtection.None,
                Random);
            generator.AddUserId(userId, PgpSignature.PositiveCertification, null, null);

            var kem = new MLKem768X25519PrivateKeyParameters(Random);
            generator.AddSubKey(new PgpKeyPair(6, PublicKeyAlgorithmTag.MLKem768_X25519, kem.GeneratePublicKey(), kem,
                DateTime.UtcNow.AddMinutes(-5)),
                Hashed(PgpKeyFlags.CanEncryptCommunications | PgpKeyFlags.CanEncryptStorage, subkeyExpiration), null);
            generator.AddSubKey(new PgpKeyPair(6, PublicKeyAlgorithmTag.Ed25519, NewEd25519(),
                DateTime.UtcNow.AddMinutes(-5)), Hashed(PgpKeyFlags.CanSign), null);
            // through the encoding, as when loading from storage: in a ring kept from the generator, the subkeys
            // carry public key packets of the primary key type (unchanged, pre-existing behaviour)
            return new PgpSecretKeyRing(generator.GenerateSecretKeyRing().GetEncoded());
        }

        private static PgpPublicKeyRing PublicRing(PgpSecretKeyRing secretRing)
        {
            var output = new MemoryStream();
            foreach (PgpPublicKey key in secretRing.GetPublicKeys())
            {
                key.Encode(output);
            }
            return new PgpPublicKeyRing(output.ToArray());
        }

        private static byte[] Encoded(PgpSecretKeyRing secretRing)
        {
            var output = new MemoryStream();
            foreach (PgpPublicKey key in secretRing.GetPublicKeys())
            {
                key.Encode(output);
            }
            return output.ToArray();
        }

        private static readonly string[][] RfcKeyPairs =
        {
            new[]{ "rfc9580", "a4-v6-secret-key.asc", "a3-v6-certificate.asc" },
            new[]{ "rfc9980", "a1-secret-key.asc", "a1-public-key.asc" },
            new[]{ "rfc9980", "a2-secret-key.asc", "a2-public-key.asc" },
            new[]{ "rfc9980", "a3-secret-key.asc", "a3-public-key.asc" },
            new[]{ "rfc9980", "a4-secret-key.asc", "a4-public-key.asc" },
            new[]{ "rfc9980", "a5-secret-key.asc", "a5-public-key.asc" },
            new[]{ "rfc9980", "a6-secret-key.asc", "a6-public-key.asc" },
            new[]{ "rfc9980", "a7-secret-key.asc", "a7-public-key.asc" },
        };

        /// <summary>
        /// The certificate extracted from each RFC transferable secret key equals the RFC certificate.
        /// </summary>
        [TestCaseSource(nameof(RfcKeyPairs))]
        public void PublicPartOfRfcSecretKeysEqualsRfcCertificate(string directory, string secretFile,
            string publicFile)
        {
            var secretRing = new PgpSecretKeyRing(PgpV6TestUtilities.LoadVector(directory, secretFile));
            byte[] certificate = PgpV6TestUtilities.LoadVector(directory, publicFile);

            Assert.That(Encoded(secretRing), Is.EqualTo(certificate));
            Assert.That(new PgpPublicKeyRing(certificate).GetEncoded(), Is.EqualTo(certificate));
            Assert.That(PublicRing(secretRing).GetEncoded(), Is.EqualTo(certificate));

            // and every secret key is consistent with its public key
            foreach (PgpSecretKey secretKey in secretRing.GetSecretKeys())
            {
                PgpPrivateKey privateKey = secretKey.ExtractPrivateKey(new char[0]);
                Assert.That(privateKey.KeyId, Is.EqualTo(secretKey.KeyId));
                Assert.That(privateKey.PublicKeyPacket.GetEncodedContents(),
                    Is.EqualTo(secretKey.PublicKey.PublicKeyPacket.GetEncodedContents()));
            }
        }

        /// <summary>
        /// The data hashed for a certification over a key and user ID, computed independently (RFC 9580 5.2.4). The
        /// key part depends on the version of the <em>signature</em>: 0x9B and a 4-octet length for v6 signatures,
        /// 0x99 and a 2-octet length for v4 signatures, whatever the version of the certified key.
        /// </summary>
        private static byte[] CertificationDigest(PgpSignature signature, PgpPublicKey key, string userId)
        {
            IDigest digest = DigestUtilities.GetDigest(PgpUtilities.GetDigestName(signature.HashAlgorithm));
            var data = new MemoryStream();
            if (signature.Version == 6)
            {
                byte[] salt = signature.GetSalt();
                data.Write(salt, 0, salt.Length);
            }

            byte[] keyBody = key.PublicKeyPacket.GetEncodedContents();
            if (signature.Version == 6)
            {
                data.WriteByte(0x9B);
                data.Write(Org.BouncyCastle.Crypto.Utilities.Pack.UInt32_To_BE((uint)keyBody.Length), 0, 4);
            }
            else
            {
                data.WriteByte(0x99);
                data.WriteByte((byte)(keyBody.Length >> 8));
                data.WriteByte((byte)keyBody.Length);
            }
            data.Write(keyBody, 0, keyBody.Length);

            byte[] id = Strings.ToUtf8ByteArray(userId);
            data.WriteByte(0xB4);
            data.Write(Org.BouncyCastle.Crypto.Utilities.Pack.UInt32_To_BE((uint)id.Length), 0, 4);
            data.Write(id, 0, id.Length);

            byte[] trailer = signature.GetSignatureTrailer();
            data.Write(trailer, 0, trailer.Length);

            byte[] all = data.ToArray();
            digest.BlockUpdate(all, 0, all.Length);
            return DigestUtilities.DoFinal(digest);
        }

        private static PgpSignature Certify(PgpKeyPair signer, HashAlgorithmTag hash, string userId,
            PgpPublicKey key)
        {
            var generator = new PgpSignatureGenerator(signer.PublicKey.Algorithm, hash);
            generator.InitSign(PgpSignature.CasualCertification, signer.PrivateKey, Random);
            return generator.GenerateCertification(userId, key);
        }

        /// <summary>
        /// Third-party certifications in all four combinations of signer and certified key versions: the hashed data
        /// matches the independent computation, the certification survives being added to the certificate, encoded
        /// and parsed again, and it verifies; the same certification on another user ID does not.
        /// </summary>
        [Test]
        public void ThirdPartyCertificationsAcrossKeyVersions(
            [Values(4, 6)] int signerVersion, [Values(4, 6)] int certifiedVersion)
        {
            var signer = new PgpKeyPair(signerVersion,
                signerVersion == 6 ? PublicKeyAlgorithmTag.Ed25519 : PublicKeyAlgorithmTag.EdDsa_Legacy, NewEd25519(),
                DateTime.UtcNow);
            const string userId = "Bob <bob@example.org>";

            PgpPublicKeyRing certified;
            if (certifiedVersion == 6)
            {
                certified = PublicRing(NewV6Ring(userId));
            }
            else
            {
                certified = PgpMLKemX25519Test.A2PublicRing();
            }
            PgpPublicKey certifiedKey = certified.GetPublicKey();
            string certifiedId = certifiedKey.GetUserIds().Cast<string>().First();

            PgpSignature certification = Certify(signer, HashAlgorithmTag.Sha512, certifiedId, certifiedKey);
            Assert.That(certification.Version, Is.EqualTo(signerVersion));

            byte[] expected = CertificationDigest(certification, certifiedKey, certifiedId);
            Assert.That(certification.GetDigestPrefix(), Is.EqualTo(Arrays.CopyOfRange(expected, 0, 2)),
                "hashed data of the certification");

            PgpPublicKey updated = PgpPublicKey.AddCertification(certifiedKey, certifiedId, certification);
            var reparsed = new PgpPublicKeyRing(PgpPublicKeyRing.InsertPublicKey(certified, updated).GetEncoded());
            PgpSignature found = reparsed.GetPublicKey().GetSignaturesForId(certifiedId)
                .Single(s => s.KeyId == signer.PublicKey.KeyId);

            found.InitVerify(signer.PublicKey);
            Assert.That(found.VerifyCertification(certifiedId, reparsed.GetPublicKey()), Is.True);

            found.InitVerify(signer.PublicKey);
            Assert.That(found.VerifyCertification("Mallory <mallory@example.org>", reparsed.GetPublicKey()),
                Is.False);

            // the certification can be removed again, leaving the original certificate
            PgpPublicKey removed = PgpPublicKey.RemoveCertification(reparsed.GetPublicKey(), certifiedId, found);
            Assert.That(removed.GetSignaturesForId(certifiedId).Any(s => s.KeyId == signer.PublicKey.KeyId), Is.False);
            Assert.That(removed.GetEncoded(), Is.EqualTo(certifiedKey.GetEncoded()));
        }

        /// <summary>Key, subkey and certification revocations made by a version 6 key.</summary>
        [Test]
        public void RevocationsOfVersion6Keys()
        {
            PgpSecretKeyRing secretRing = NewV6Ring("Carol <carol@example.org>");
            PgpPublicKeyRing publicRing = PublicRing(secretRing);
            PgpPublicKey primary = publicRing.GetPublicKey();
            PgpPrivateKey primaryPrivate = secretRing.GetSecretKey().ExtractPrivateKey(new char[0]);
            PgpPublicKey subkey = publicRing.GetPublicKeys()
                .First(k => k.Algorithm == PublicKeyAlgorithmTag.MLKem768_X25519);
            Assert.That(primary.IsRevoked(), Is.False);

            // subkey revocation (0x28): primary key, then subkey
            var subGen = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha256);
            subGen.InitSign(PgpSignature.SubkeyRevocation, primaryPrivate, Random);
            PgpSignature subkeyRevocation = subGen.GenerateCertification(primary, subkey);
            Assert.That(subkeyRevocation.Version, Is.EqualTo(6));
            PgpPublicKey revokedSubkey = PgpPublicKey.AddCertification(subkey, subkeyRevocation);
            Assert.That(revokedSubkey.IsRevoked(), Is.True);

            // key revocation (0x20)
            var keyGen = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha256);
            keyGen.InitSign(PgpSignature.KeyRevocation, primaryPrivate, Random);
            PgpSignature keyRevocation = keyGen.GenerateCertification(primary);
            PgpPublicKey revokedPrimary = PgpPublicKey.AddCertification(primary, keyRevocation);
            Assert.That(revokedPrimary.IsRevoked(), Is.True);

            // certification revocation (0x30) of the user ID
            var uidGen = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha256);
            uidGen.InitSign(PgpSignature.CertificationRevocation, primaryPrivate, Random);
            PgpSignature uidRevocation = uidGen.GenerateCertification("Carol <carol@example.org>", primary);
            revokedPrimary = PgpPublicKey.AddCertification(revokedPrimary, "Carol <carol@example.org>", uidRevocation);

            PgpPublicKeyRing revokedRing = PgpPublicKeyRing.InsertPublicKey(
                PgpPublicKeyRing.InsertPublicKey(publicRing, revokedPrimary), revokedSubkey);
            var reparsed = new PgpPublicKeyRing(revokedRing.GetEncoded());

            PgpPublicKey reparsedPrimary = reparsed.GetPublicKey();
            Assert.That(reparsedPrimary.IsRevoked(), Is.True);
            PgpSignature keyRev = reparsedPrimary.GetSignaturesOfType(PgpSignature.KeyRevocation).Single();
            keyRev.InitVerify(reparsedPrimary);
            Assert.That(keyRev.VerifyCertification(reparsedPrimary), Is.True);

            PgpPublicKey reparsedSubkey = reparsed.GetPublicKey(subkey.KeyId);
            Assert.That(reparsedSubkey.IsRevoked(), Is.True);
            PgpSignature subRev = reparsedSubkey.GetSignaturesOfType(PgpSignature.SubkeyRevocation).Single();
            subRev.InitVerify(reparsedPrimary);
            Assert.That(subRev.VerifyCertification(reparsedPrimary, reparsedSubkey), Is.True);

            PgpSignature uidRev = reparsedPrimary.GetSignaturesForId("Carol <carol@example.org>")
                .Single(s => s.SignatureType == PgpSignature.CertificationRevocation);
            uidRev.InitVerify(reparsedPrimary);
            Assert.That(uidRev.VerifyCertification("Carol <carol@example.org>", reparsedPrimary), Is.True);

            // a revocation of the subkey made by an unrelated v6 key does not verify
            var other = new PgpKeyPair(6, PublicKeyAlgorithmTag.Ed25519, NewEd25519(), DateTime.UtcNow);
            var forged = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha256);
            forged.InitSign(PgpSignature.SubkeyRevocation, other.PrivateKey, Random);
            PgpSignature forgedRevocation = forged.GenerateCertification(primary, subkey);
            forgedRevocation.InitVerify(primary);
            Assert.That(forgedRevocation.VerifyCertification(primary, subkey), Is.False);
        }

        /// <summary>
        /// Adding and removing subkeys, merging copies with different signatures, replacing public keys.
        /// </summary>
        [Test]
        public void RingSurgeryOnVersion6Rings()
        {
            PgpSecretKeyRing secretRing = NewV6Ring("Dave <dave@example.org>");
            PgpPublicKeyRing publicRing = PublicRing(secretRing);
            PgpPublicKey subkey = publicRing.GetPublicKeys().First(k => k.Algorithm == PublicKeyAlgorithmTag.Ed25519 &&
                !k.IsMasterKey);

            // remove and re-insert a subkey
            PgpPublicKeyRing without = PgpPublicKeyRing.RemovePublicKey(publicRing, subkey);
            Assert.That(without.GetPublicKeys().Count(), Is.EqualTo(2));
            Assert.That(without.GetPublicKey(subkey.KeyId), Is.Null);
            PgpPublicKeyRing with = PgpPublicKeyRing.InsertPublicKey(without, subkey);
            Assert.That(with.GetPublicKey(subkey.KeyId).GetFingerprint(), Is.EqualTo(subkey.GetFingerprint()));

            // the same for secret keys
            PgpSecretKey secretSubkey = secretRing.GetSecretKey(subkey.KeyId);
            PgpSecretKeyRing secretWithout = PgpSecretKeyRing.RemoveSecretKey(secretRing, secretSubkey);
            Assert.That(secretWithout.GetSecretKey(subkey.KeyId), Is.Null);
            PgpSecretKeyRing secretWith = PgpSecretKeyRing.InsertSecretKey(secretWithout, secretSubkey);
            Assert.That(secretWith.GetSecretKey(subkey.KeyId).ExtractPrivateKey(new char[0]), Is.Not.Null);

            // a copy with an extra third-party certification merges with the original
            var signer = new PgpKeyPair(6, PublicKeyAlgorithmTag.Ed25519, NewEd25519(), DateTime.UtcNow);
            PgpSignature certification = Certify(signer, HashAlgorithmTag.Sha256, "Dave <dave@example.org>",
                publicRing.GetPublicKey());
            PgpPublicKeyRing certifiedCopy = PgpPublicKeyRing.InsertPublicKey(publicRing,
                PgpPublicKey.AddCertification(publicRing.GetPublicKey(), "Dave <dave@example.org>", certification));
            PgpPublicKeyRing merged = PgpPublicKeyRing.Join(publicRing, certifiedCopy);
            Assert.That(merged.GetPublicKey().GetSignaturesForId("Dave <dave@example.org>").Count(), Is.EqualTo(2));
            Assert.That(PgpPublicKeyRing.Join(merged, certifiedCopy).GetEncoded(), Is.EqualTo(merged.GetEncoded()),
                "merging again adds nothing");

            // the secret ring takes the merged public keys and stays usable
            PgpSecretKeyRing replaced = PgpSecretKeyRing.ReplacePublicKeys(secretRing, merged);
            Assert.That(replaced.GetPublicKey().GetSignaturesForId("Dave <dave@example.org>").Count(), Is.EqualTo(2));
            foreach (PgpSecretKey secretKey in replaced.GetSecretKeys())
            {
                Assert.That(secretKey.ExtractPrivateKey(new char[0]), Is.Not.Null);
            }
            Assert.That(new PgpSecretKeyRing(replaced.GetEncoded()).GetEncoded(), Is.EqualTo(replaced.GetEncoded()));
        }

        /// <summary>
        /// Bundles of v4 and v6 rings: lookups by key ID (the leftmost 8 octets of a v6 fingerprint, the rightmost
        /// of a v4 one) and by fingerprint, for primary keys and subkeys, and by the key ID of a v6 PKESK.
        /// </summary>
        [Test]
        public void BundlesFindVersion6KeysByKeyIdAndFingerprint()
        {
            var a1Secret = new PgpSecretKeyRing(PgpV6TestUtilities.LoadRfc9980("a1-secret-key.asc"));
            var a2Secret = PgpMLKemX25519Test.A2SecretRing();
            PgpSecretKeyRing generated = NewV6Ring("Erin <erin@example.org>");

            var secretBundle = new PgpSecretKeyRingBundle(Arrays.ConcatenateAll(a1Secret.GetEncoded(),
                a2Secret.GetEncoded(), generated.GetEncoded()));
            var publicBundle = new PgpPublicKeyRingBundle(Arrays.ConcatenateAll(Encoded(a1Secret), Encoded(a2Secret),
                Encoded(generated)));
            Assert.That(publicBundle.Count, Is.EqualTo(3));

            foreach (PgpSecretKeyRing ring in new[]{ a1Secret, a2Secret, generated })
            {
                foreach (PgpPublicKey key in ring.GetPublicKeys())
                {
                    byte[] fingerprint = key.GetFingerprint();
                    long expectedKeyId = key.Version == 6
                        ? (long)Org.BouncyCastle.Crypto.Utilities.Pack.BE_To_UInt64(fingerprint, 0)
                        : (long)Org.BouncyCastle.Crypto.Utilities.Pack.BE_To_UInt64(fingerprint,
                            fingerprint.Length - 8);
                    Assert.That(key.KeyId, Is.EqualTo(expectedKeyId));
                    Assert.That(publicBundle.Contains(key.KeyId), Is.True);
                    Assert.That(publicBundle.GetPublicKey(key.KeyId).GetFingerprint(), Is.EqualTo(fingerprint));
                    Assert.That(publicBundle.GetPublicKey(fingerprint).KeyId, Is.EqualTo(key.KeyId));
                    Assert.That(publicBundle.GetPublicKeyRing(key.KeyId).GetPublicKey().KeyId,
                        Is.EqualTo(ring.GetPublicKey().KeyId));
                    Assert.That(secretBundle.GetSecretKey(key.KeyId).KeyId, Is.EqualTo(key.KeyId));
                }
            }

            Assert.That(publicBundle.GetKeyRings("erin@example.org", true).Count(), Is.EqualTo(1));

            // the RFC 9980 A.1.3 message: find the key by the PKESK's key ID, then decrypt
            byte[] message = PgpV6TestUtilities.LoadRfc9980("a1-message.asc");
            var list = (PgpEncryptedDataList)new PgpObjectFactory(message).NextPgpObject();
            var encData = (PgpPublicKeyEncryptedData)list[0];
            PgpSecretKey secretKey = secretBundle.GetSecretKey(encData.KeyId);
            Assert.That(secretKey, Is.Not.Null);
            Assert.That(secretKey.PublicKey.GetFingerprint(), Is.EqualTo(encData.GetKeyFingerprint()));
            Assert.That(encData.GetDataStream(secretKey.ExtractPrivateKey(new char[0])), Is.Not.Null);
        }

        /// <summary>
        /// Pass phrases with non-ASCII characters: the raw octets decide. A key protected with the UTF-8 encoding is
        /// opened with the UTF-8 and raw methods, but not with the legacy character conversion; the same for v6
        /// SKESKs. An empty pass phrase is a valid pass phrase.
        /// </summary>
        [Test]
        public void PassPhraseEncodings()
        {
            const string passPhrase = "pässwörd 中文 \U0001F511";
            byte[] utf8 = Strings.ToUtf8ByteArray(passPhrase);

            PgpSecretKeyRing ring = NewV6Ring("Frank <frank@example.org>", PgpSecretKeyProtection.AeadArgon2(
                SymmetricKeyAlgorithmTag.Aes256, AeadAlgorithmTag.Ocb, new S2k.Argon2Params(1, 1, 10, Random), utf8));
            foreach (PgpSecretKey key in ring.GetSecretKeys())
            {
                Assert.That(key.S2kUsage, Is.EqualTo(SecretKeyPacket.UsageAead));
                Assert.That(key.ExtractPrivateKeyUtf8(passPhrase.ToCharArray()), Is.Not.Null);
                Assert.That(key.ExtractPrivateKeyRaw(utf8), Is.Not.Null);
                // the legacy conversion (Convert.ToByte per character) cannot represent characters above U+00FF
                // and throws, as it always has for every key version
                Assert.Throws<OverflowException>(() => key.ExtractPrivateKey(passPhrase.ToCharArray()));
            }

            // characters up to U+00FF: the legacy conversion gives other octets than UTF-8, so the key stays locked
            const string latin1 = "pässwörd";
            PgpSecretKeyRing latinRing = NewV6Ring("Fiona <fiona@example.org>", PgpSecretKeyProtection.AeadArgon2(
                SymmetricKeyAlgorithmTag.Aes128, AeadAlgorithmTag.Gcm, new S2k.Argon2Params(1, 1, 10, Random),
                Strings.ToUtf8ByteArray(latin1)));
            foreach (PgpSecretKey key in latinRing.GetSecretKeys())
            {
                Assert.That(key.ExtractPrivateKeyUtf8(latin1.ToCharArray()), Is.Not.Null);
                Assert.Catch<PgpException>(() => key.ExtractPrivateKey(latin1.ToCharArray()));
            }

            PgpSecretKeyRing empty = NewV6Ring("Gina <gina@example.org>", PgpSecretKeyProtection.AeadIterated(
                SymmetricKeyAlgorithmTag.Aes128, AeadAlgorithmTag.Eax, HashAlgorithmTag.Sha256, 0x60, new byte[0]));
            foreach (PgpSecretKey key in empty.GetSecretKeys())
            {
                Assert.That(key.S2kUsage, Is.EqualTo(SecretKeyPacket.UsageAead));
                Assert.That(key.ExtractPrivateKey(new char[0]), Is.Not.Null);
                Assert.Catch<PgpException>(() => key.ExtractPrivateKey("x".ToCharArray()));
            }

            byte[] content = Strings.ToUtf8ByteArray("secret");
            var generator = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, AeadAlgorithmTag.Ocb,
                Random);
            generator.AddMethodUtf8(passPhrase.ToCharArray(), new S2k.Argon2Params(1, 1, 10, Random));
            var output = new MemoryStream();
            using (Stream encOut = generator.Open(output, new byte[256]))
            using (Stream litOut = new PgpLiteralDataGenerator().Open(encOut, PgpLiteralData.Binary, "", content.Length,
                DateTime.UtcNow))
            {
                litOut.Write(content, 0, content.Length);
            }

            PgpPbeEncryptedData Pbe() => (PgpPbeEncryptedData)((PgpEncryptedDataList)new PgpObjectFactory(
                output.ToArray()).NextPgpObject())[0];

            var literal = (PgpLiteralData)new PgpObjectFactory(Pbe().GetDataStreamUtf8(passPhrase.ToCharArray()))
                .NextPgpObject();
            Assert.That(Streams.ReadAll(literal.GetDataStream()), Is.EqualTo(content));
            Assert.Throws<OverflowException>(() => Pbe().GetDataStream(passPhrase.ToCharArray()));
            Assert.That(Pbe().GetDataStreamRaw(utf8), Is.Not.Null);
        }

        /// <summary>
        /// Changing the pass phrase of a whole v6 ring keeps every key usable and the public part intact.
        /// </summary>
        [Test]
        public void RingPassPhraseChange()
        {
            byte[] oldPass = Strings.ToUtf8ByteArray("old");
            PgpSecretKeyRing ring = NewV6Ring("Hank <hank@example.org>", PgpSecretKeyProtection.AeadArgon2(
                SymmetricKeyAlgorithmTag.Aes256, AeadAlgorithmTag.Gcm, new S2k.Argon2Params(1, 1, 10, Random),
                oldPass));

            PgpSecretKeyRing changed = PgpSecretKeyRing.CopyWithNewPassword(ring, "old".ToCharArray(),
                "new".ToCharArray(), SymmetricKeyAlgorithmTag.Aes256, Random);
            Assert.That(Encoded(changed), Is.EqualTo(Encoded(ring)), "public part unchanged");
            foreach (PgpSecretKey key in changed.GetSecretKeys())
            {
                Assert.That(key.S2kUsage, Is.Not.EqualTo(SecretKeyPacket.UsageChecksum), "never usage 255 for v6");
                Assert.That(key.ExtractPrivateKey("new".ToCharArray()), Is.Not.Null);
                Assert.Catch<PgpException>(() => key.ExtractPrivateKey("old".ToCharArray()));
            }

            // and back to AEAD with a fresh protection object, key by key
            foreach (PgpSecretKey key in changed.GetSecretKeys())
            {
                PgpSecretKey aead = PgpSecretKey.CopyWithNewProtection(key, Strings.ToUtf8ByteArray("new"),
                    PgpSecretKeyProtection.AeadIterated(SymmetricKeyAlgorithmTag.Aes128, AeadAlgorithmTag.Ocb,
                        HashAlgorithmTag.Sha256, 0x60, Strings.ToUtf8ByteArray("third")), Random);
                Assert.That(aead.S2kUsage, Is.EqualTo(SecretKeyPacket.UsageAead));
                Assert.That(aead.ExtractPrivateKey("third".ToCharArray()), Is.Not.Null);
                Assert.That(aead.PublicKey.GetEncoded(), Is.EqualTo(key.PublicKey.GetEncoded()));
            }
        }

        /// <summary>Validity of v6 subkeys comes from verified v6 binding signatures.</summary>
        [Test]
        public void SubkeyExpiryFromVersion6Binding()
        {
            const long fiveDays = 5L * 24 * 60 * 60;
            PgpSecretKeyRing ring = NewV6Ring("Ivy <ivy@example.org>", subkeyExpiration: fiveDays);
            PgpPublicKeyRing publicRing = PublicRing(ring);
            PgpPublicKey subkey = publicRing.GetPublicKeys()
                .First(k => k.Algorithm == PublicKeyAlgorithmTag.MLKem768_X25519);
            Assert.That(publicRing.GetValidSeconds(subkey), Is.EqualTo(fiveDays));
            Assert.That(publicRing.GetValidSeconds(publicRing.GetPublicKeys().Last()), Is.EqualTo(0));

            // a forged binding with a different expiry, made by another key, is not trusted
            var other = new PgpKeyPair(6, PublicKeyAlgorithmTag.Ed25519, NewEd25519(), DateTime.UtcNow);
            var forgedGen = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha256);
            var subpackets = new PgpSignatureSubpacketGenerator();
            subpackets.SetKeyExpirationTime(true, 1);
            subpackets.SetSignatureCreationTime(false, DateTime.UtcNow.AddMinutes(1));
            forgedGen.SetHashedSubpackets(subpackets.Generate());
            forgedGen.InitSign(PgpSignature.SubkeyBinding, other.PrivateKey, Random);
            PgpSignature forged = forgedGen.GenerateCertification(publicRing.GetPublicKey(), subkey);
            PgpPublicKeyRing tampered = PgpPublicKeyRing.InsertPublicKey(publicRing,
                PgpPublicKey.AddCertification(subkey, forged));
            Assert.That(tampered.GetValidSeconds(tampered.GetPublicKey(subkey.KeyId)), Is.EqualTo(fiveDays));
        }
    }
}
