using System;
using System.Linq;

using NUnit.Framework;

using Org.BouncyCastle.Bcpg.Attr;
using Org.BouncyCastle.Bcpg.Sig;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    /// <summary>Tests for the selection of the message format and of the algorithms from certificates.</summary>
    [TestFixture]
    public class PgpEncryptionPreferencesTest
    {
        private static readonly SecureRandom Random = new SecureRandom();

        private const byte FeatureMdc = 0x01;
        private const byte BothFeatures = 0x01 | 0x08; // modification detection and SEIPD v2

        private static readonly byte[] Content = Strings.ToUtf8ByteArray("preferences");

        private static PreferredAeadCiphersuites.Combination Suite(SymmetricKeyAlgorithmTag cipher,
            AeadAlgorithmTag aead) => new PreferredAeadCiphersuites.Combination(cipher, aead);

        private static PgpSignatureSubpacketVector Packets(SymmetricKeyAlgorithmTag[] ciphers,
            PreferredAeadCiphersuites.Combination[] suites, byte features, bool primary = false)
        {
            var generator = new PgpSignatureSubpacketGenerator();
            generator.SetKeyFlags(false, PgpKeyFlags.CanCertify | PgpKeyFlags.CanSign);
            if (ciphers != null)
            {
                generator.SetPreferredSymmetricAlgorithms(false, ciphers.Select(c => (int)c).ToArray());
            }
            if (suites != null)
            {
                generator.SetPreferredAeadCiphersuites(false, suites);
            }
            if (features != 0)
            {
                generator.SetFeature(false, features);
            }
            if (primary)
            {
                generator.SetPrimaryUserId(false, true);
            }
            return generator.Generate();
        }

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

        private static PgpKeyPair MLKemPair(int version)
        {
            var privateKey = new MLKem768X25519PrivateKeyParameters(Random);
            return new PgpKeyPair(version, PublicKeyAlgorithmTag.MLKem768_X25519, privateKey.GeneratePublicKey(),
                privateKey, DateTime.UtcNow);
        }

        private static PgpSignatureSubpacketVector EncryptionFlags()
        {
            var generator = new PgpSignatureSubpacketGenerator();
            generator.SetKeyFlags(false, PgpKeyFlags.CanEncryptCommunications | PgpKeyFlags.CanEncryptStorage);
            return generator.Generate();
        }

        private sealed class Cert
        {
            internal PgpPublicKeyRing Public;
            internal PgpSecretKeyRing Secret;
        }

        /// <summary>A certificate with preferences, an X25519 subkey and optionally a post-quantum subkey.</summary>
        private static Cert MakeCert(int version, SymmetricKeyAlgorithmTag[] ciphers,
            PreferredAeadCiphersuites.Combination[] suites, byte features, bool postQuantum = false,
            bool xdh = true)
        {
            PgpSignatureSubpacketVector preferences = Packets(ciphers, suites, features);
            PgpKeyRingGenerator generator;
            if (version == 6)
            {
                generator = new PgpKeyRingGenerator(EdDsaPair(6), HashAlgorithmTag.Sha256, preferences, null,
                    PgpSecretKeyProtection.None, Random);
            }
            else
            {
                // version 4 certificates keep their preferences in the certification of the user ID
                generator = new PgpKeyRingGenerator(EdDsaPair(4), HashAlgorithmTag.Sha256, Packets(null, null, 0),
                    null, PgpSecretKeyProtection.None, Random);
                generator.AddUserId("v4 <v4@example.org>", PgpSignature.PositiveCertification, preferences, null);
            }

            if (xdh)
            {
                generator.AddSubKey(X25519Pair(version), EncryptionFlags(), null);
            }
            if (postQuantum)
            {
                generator.AddSubKey(MLKemPair(version), EncryptionFlags(), null);
            }

            return new Cert
            {
                Public = new PgpPublicKeyRing(generator.GeneratePublicKeyRing().GetEncoded()),
                Secret = new PgpSecretKeyRing(generator.GenerateSecretKeyRing().GetEncoded()),
            };
        }

        private static PgpEncryptionPreferences Select(params Cert[] certs) =>
            PgpEncryptionPreferences.Select(certs.Select(c => c.Public));

        private static readonly SymmetricKeyAlgorithmTag[] Aes256First =
        {
            SymmetricKeyAlgorithmTag.Aes256, SymmetricKeyAlgorithmTag.Aes128,
        };

        [Test]
        public void AllRecipientsSupportingSeipdV2()
        {
            Cert a = MakeCert(6, Aes256First, new[]{ Suite(SymmetricKeyAlgorithmTag.Aes256, AeadAlgorithmTag.Ocb) },
                BothFeatures);
            Cert b = MakeCert(4, Aes256First, new[]
            {
                Suite(SymmetricKeyAlgorithmTag.Aes256, AeadAlgorithmTag.Gcm),
                Suite(SymmetricKeyAlgorithmTag.Aes256, AeadAlgorithmTag.Ocb),
            }, BothFeatures);

            PgpEncryptionPreferences result = Select(a, b);
            Assert.That(result.UseSeipdV2, Is.True);
            Assert.That(result.SymmetricAlgorithm, Is.EqualTo(SymmetricKeyAlgorithmTag.Aes256));
            Assert.That(result.AeadAlgorithm, Is.EqualTo(AeadAlgorithmTag.Ocb));

            // the generator makes a version 2 message, and both recipients can read it
            byte[] message = Encrypt(result, a, b);
            var list = (PgpEncryptedDataList)new PgpObjectFactory(message).NextPgpObject();
            Assert.That(list.GetEncryptedDataObjects().Cast<PgpPublicKeyEncryptedData>().All(d => d.Version == 6),
                Is.True);
            foreach (Cert cert in new[]{ a, b })
            {
                Assert.That(Decrypt(message, cert), Is.EqualTo(Content));
            }
        }

        private static byte[] Encrypt(PgpEncryptionPreferences preferences, params Cert[] recipients)
        {
            PgpEncryptedDataGenerator generator = preferences.CreateGenerator(Random);
            foreach (Cert recipient in recipients)
            {
                generator.AddMethod(recipient.Public.GetPublicKeys().First(k => k.IsEncryptionKey));
            }

            var bOut = new System.IO.MemoryStream();
            using (System.IO.Stream encrypted = generator.Open(bOut, new byte[1 << 10]))
            using (System.IO.Stream literal = new PgpLiteralDataGenerator().Open(encrypted, PgpLiteralData.Binary, "",
                DateTime.UtcNow, new byte[1 << 10]))
            {
                literal.Write(Content, 0, Content.Length);
            }
            return bOut.ToArray();
        }

        private static byte[] Decrypt(byte[] message, Cert recipient)
        {
            PgpSecretKey key = recipient.Secret.GetSecretKeys().First(k => k.PublicKey.IsEncryptionKey);
            return PgpMLKemX25519Test.Decrypt(message, key.ExtractPrivateKey(null)).Content;
        }

        [Test]
        public void OneRecipientWithoutSeipdV2()
        {
            var ocb = new[]{ Suite(SymmetricKeyAlgorithmTag.Aes256, AeadAlgorithmTag.Ocb) };
            Cert modern = MakeCert(6, Aes256First, ocb, BothFeatures);
            Cert old = MakeCert(4, Aes256First, null, FeatureMdc);

            PgpEncryptionPreferences result = Select(modern, old);
            Assert.That(result.UseSeipdV2, Is.False);
            Assert.That(result.SymmetricAlgorithm, Is.EqualTo(SymmetricKeyAlgorithmTag.Aes256));

            byte[] message = Encrypt(result, modern, old);
            var list = (PgpEncryptedDataList)new PgpObjectFactory(message).NextPgpObject();
            Assert.That(list.GetEncryptedDataObjects().Cast<PgpPublicKeyEncryptedData>().All(d => d.Version == 3),
                Is.True);
            Assert.That(Decrypt(message, modern), Is.EqualTo(Content));
            Assert.That(Decrypt(message, old), Is.EqualTo(Content));
        }

        [Test]
        public void PostQuantumCertificatesImplyAes256()
        {
            // the certificate only lists Camellia-128 (and AES-128, which is always supported)
            var ciphers = new[]{ SymmetricKeyAlgorithmTag.Camellia128 };
            var suites = new[]{ Suite(SymmetricKeyAlgorithmTag.Camellia128, AeadAlgorithmTag.Gcm) };

            Cert pq = MakeCert(6, ciphers, suites, BothFeatures, postQuantum: true);
            PgpEncryptionPreferences result = Select(pq);
            Assert.That(result.UseSeipdV2, Is.True);
            Assert.That(result.SymmetricAlgorithm, Is.EqualTo(SymmetricKeyAlgorithmTag.Aes256));
            Assert.That(result.AeadAlgorithm, Is.EqualTo(AeadAlgorithmTag.Ocb));

            // and the same for a version 4 certificate without version 2 SEIPD
            Cert v4 = MakeCert(4, ciphers, null, FeatureMdc, postQuantum: true);
            result = Select(v4);
            Assert.That(result.UseSeipdV2, Is.False);
            Assert.That(result.SymmetricAlgorithm, Is.EqualTo(SymmetricKeyAlgorithmTag.Aes256));

            // a classic certificate with the same lists does not get AES-256
            Cert classic = MakeCert(6, ciphers, suites, BothFeatures);
            result = Select(classic);
            Assert.That(result.SymmetricAlgorithm, Is.EqualTo(SymmetricKeyAlgorithmTag.Camellia128));
            Assert.That(result.AeadAlgorithm, Is.EqualTo(AeadAlgorithmTag.Gcm));
        }

        // RFC 9580 13.7: a version 6 certificate without a Features subpacket gets version 2 SEIPD
        [Test]
        public void Version6CertificatesWithoutFeaturesGetSeipdV2()
        {
            var ocb = new[]{ Suite(SymmetricKeyAlgorithmTag.Aes256, AeadAlgorithmTag.Ocb) };
            Cert v6 = MakeCert(6, Aes256First, ocb, 0);
            PgpEncryptionPreferences result = Select(v6);
            Assert.That(result.UseSeipdV2, Is.True);
            Assert.That(Decrypt(Encrypt(result, v6), v6), Is.EqualTo(Content));

            // but not if it says otherwise, and not for a version 4 certificate
            Assert.That(Select(MakeCert(6, Aes256First, ocb, FeatureMdc)).UseSeipdV2, Is.False);
            Assert.That(Select(MakeCert(4, Aes256First, ocb, 0)).UseSeipdV2, Is.False);
            Assert.That(Select(v6, MakeCert(4, Aes256First, ocb, 0)).UseSeipdV2, Is.False);
        }

        // Anybody can append a subkey to a certificate: one without a binding signature does not make it post-quantum
        [Test]
        public void UnboundPostQuantumSubkeysAreIgnored()
        {
            var ciphers = new[]{ SymmetricKeyAlgorithmTag.Camellia128 };
            var suites = new[]{ Suite(SymmetricKeyAlgorithmTag.Camellia128, AeadAlgorithmTag.Gcm) };
            Cert classic = MakeCert(6, ciphers, suites, BothFeatures);

            var mlKem = new MLKem768X25519PrivateKeyParameters(Random).GeneratePublicKey();
            var unbound = new PgpPublicKey(new PublicSubkeyPacket(PublicKeyPacket.Version6,
                PublicKeyAlgorithmTag.MLKem768_X25519, DateTime.UtcNow, new MLKem768X25519PublicBcpgKey(
                    Arrays.Concatenate(mlKem.X25519Key.GetEncoded(), mlKem.MLKemKey.GetEncoded()))));
            var appended = new PgpPublicKeyRing(PgpPublicKeyRing.InsertPublicKey(classic.Public, unbound)
                .GetEncoded());
            Assert.That(appended.GetPublicKeys().Count(), Is.EqualTo(3));

            PgpEncryptionPreferences result = PgpEncryptionPreferences.Select(new[]{ appended });
            Assert.That(result.SymmetricAlgorithm, Is.EqualTo(SymmetricKeyAlgorithmTag.Camellia128));
            Assert.That(result.AeadAlgorithm, Is.EqualTo(AeadAlgorithmTag.Gcm));

            // with a binding signature it counts
            Cert bound = MakeCert(6, ciphers, suites, BothFeatures, postQuantum: true);
            Assert.That(Select(bound).SymmetricAlgorithm, Is.EqualTo(SymmetricKeyAlgorithmTag.Aes256));
        }

        [Test]
        public void Aes256IsPreferredWhenEverybodySupportsIt()
        {
            var camelliaFirst = new[]{ SymmetricKeyAlgorithmTag.Camellia256, SymmetricKeyAlgorithmTag.Aes256 };
            Cert a = MakeCert(4, camelliaFirst, null, FeatureMdc);
            Cert b = MakeCert(4, camelliaFirst, null, FeatureMdc);

            Assert.That(Select(a, b).SymmetricAlgorithm, Is.EqualTo(SymmetricKeyAlgorithmTag.Aes256));

            // without AES-256 in every list, the first common one in the order of the first certificate
            Cert c = MakeCert(4, new[]{ SymmetricKeyAlgorithmTag.Camellia256 }, null,
                FeatureMdc, xdh: false);
            Cert d = MakeCert(4, new[]{ SymmetricKeyAlgorithmTag.Camellia256, SymmetricKeyAlgorithmTag.Aes192 }, null,
                FeatureMdc, xdh: false);
            Assert.That(Select(c, d).SymmetricAlgorithm, Is.EqualTo(SymmetricKeyAlgorithmTag.Camellia256));
        }

        [Test]
        public void AeadModeFollowsTheFirstCertificate()
        {
            var gcmFirst = new[]
            {
                Suite(SymmetricKeyAlgorithmTag.Aes256, AeadAlgorithmTag.Gcm),
                Suite(SymmetricKeyAlgorithmTag.Aes256, AeadAlgorithmTag.Ocb),
            };
            var ocbFirst = new[]
            {
                Suite(SymmetricKeyAlgorithmTag.Aes256, AeadAlgorithmTag.Ocb),
                Suite(SymmetricKeyAlgorithmTag.Aes256, AeadAlgorithmTag.Gcm),
            };

            Cert a = MakeCert(6, Aes256First, gcmFirst, BothFeatures);
            Cert b = MakeCert(6, Aes256First, ocbFirst, BothFeatures);

            Assert.That(Select(a, b).AeadAlgorithm, Is.EqualTo(AeadAlgorithmTag.Gcm));
            Assert.That(Select(b, a).AeadAlgorithm, Is.EqualTo(AeadAlgorithmTag.Ocb));
        }

        [Test]
        public void ImplicitAes128Ocb()
        {
            var camelliaEax = new[]{ Suite(SymmetricKeyAlgorithmTag.Camellia256, AeadAlgorithmTag.Eax) };
            Cert a = MakeCert(6, Aes256First, camelliaEax, BothFeatures);
            Cert b = MakeCert(6, Aes256First, new[]{ Suite(SymmetricKeyAlgorithmTag.Twofish, AeadAlgorithmTag.Gcm) },
                BothFeatures);

            PgpEncryptionPreferences result = Select(a, b);
            Assert.That(result.UseSeipdV2, Is.True);
            Assert.That(result.SymmetricAlgorithm, Is.EqualTo(SymmetricKeyAlgorithmTag.Aes128));
            Assert.That(result.AeadAlgorithm, Is.EqualTo(AeadAlgorithmTag.Ocb));

            // a certificate without any AEAD preference
            Cert c = MakeCert(6, Aes256First, null, BothFeatures);
            result = Select(a, c);
            Assert.That(result.SymmetricAlgorithm, Is.EqualTo(SymmetricKeyAlgorithmTag.Aes128));
            Assert.That(result.AeadAlgorithm, Is.EqualTo(AeadAlgorithmTag.Ocb));
        }

        [Test]
        public void NeverOutsideTheListOfARecipient()
        {
            Cert a = MakeCert(4, new[]{ SymmetricKeyAlgorithmTag.Camellia256, SymmetricKeyAlgorithmTag.Twofish }, null,
                FeatureMdc, xdh: false);
            Cert b = MakeCert(4, new[]{ SymmetricKeyAlgorithmTag.Twofish }, null,
                FeatureMdc, xdh: false);
            Cert c = MakeCert(4, new[]{ SymmetricKeyAlgorithmTag.Camellia256 }, null,
                FeatureMdc, xdh: false);

            Assert.That(Select(a, b).SymmetricAlgorithm, Is.EqualTo(SymmetricKeyAlgorithmTag.Twofish));
            Assert.That(Select(a, c).SymmetricAlgorithm, Is.EqualTo(SymmetricKeyAlgorithmTag.Camellia256));
            // nothing in common but the implicit AES-128
            Assert.That(Select(b, c).SymmetricAlgorithm, Is.EqualTo(SymmetricKeyAlgorithmTag.Aes128));
        }

        [Test]
        public void FirstCommonPairWithoutAes256()
        {
            var shared = Suite(SymmetricKeyAlgorithmTag.Camellia192, AeadAlgorithmTag.Gcm);
            Cert a = MakeCert(6, null, new[]{ Suite(SymmetricKeyAlgorithmTag.Twofish, AeadAlgorithmTag.Eax), shared },
                BothFeatures);
            Cert b = MakeCert(6, null, new[]{ shared, Suite(SymmetricKeyAlgorithmTag.Twofish, AeadAlgorithmTag.Eax) },
                BothFeatures);

            PgpEncryptionPreferences result = Select(a, b);
            Assert.That(result.SymmetricAlgorithm, Is.EqualTo(SymmetricKeyAlgorithmTag.Twofish));
            Assert.That(result.AeadAlgorithm, Is.EqualTo(AeadAlgorithmTag.Eax));
        }

        [Test]
        public void EmptyIntersectionFallsBackToAes128()
        {
            Cert a = MakeCert(6, null, new[]{ Suite(SymmetricKeyAlgorithmTag.Twofish, AeadAlgorithmTag.Eax) },
                BothFeatures);
            Cert b = MakeCert(6, null, new[]{ Suite(SymmetricKeyAlgorithmTag.Camellia256, AeadAlgorithmTag.Gcm) },
                BothFeatures);

            PgpEncryptionPreferences result = Select(a, b);
            Assert.That(result.SymmetricAlgorithm, Is.EqualTo(SymmetricKeyAlgorithmTag.Aes128));
            Assert.That(result.AeadAlgorithm, Is.EqualTo(AeadAlgorithmTag.Ocb));

            // and for version 1 messages
            Cert c = MakeCert(4, new[]{ SymmetricKeyAlgorithmTag.Twofish }, null, 0);
            Cert d = MakeCert(4, new[]{ SymmetricKeyAlgorithmTag.Camellia256 }, null, 0);
            result = Select(c, d);
            Assert.That(result.UseSeipdV2, Is.False);
            Assert.That(result.SymmetricAlgorithm, Is.EqualTo(SymmetricKeyAlgorithmTag.Aes128));
        }

        // RFC 9580 9.3: IDEA, TripleDES and CAST5 are never chosen, even if they are all that a recipient lists
        [Test]
        public void DecryptOnlyCiphersAreNeverChosen()
        {
            foreach (var cipher in new[]
            {
                SymmetricKeyAlgorithmTag.Idea, SymmetricKeyAlgorithmTag.TripleDes, SymmetricKeyAlgorithmTag.Cast5,
            })
            {
                Cert only = MakeCert(4, new[]{ cipher }, null, 0, xdh: false);
                Assert.That(Select(only).SymmetricAlgorithm, Is.EqualTo(SymmetricKeyAlgorithmTag.Aes128),
                    cipher.ToString());

                Cert first = MakeCert(4, new[]{ cipher, SymmetricKeyAlgorithmTag.Camellia256 }, null, 0, xdh: false);
                Assert.That(Select(first).SymmetricAlgorithm, Is.EqualTo(SymmetricKeyAlgorithmTag.Camellia256),
                    cipher.ToString());
            }
        }

        // RFC 9580 5.2.3.10: a version 6 key is only used with a valid direct-key signature, and not when revoked
        [Test]
        public void Version6CertificatesNeedAValidDirectKeySignature()
        {
            var suites = new[]{ Suite(SymmetricKeyAlgorithmTag.Camellia256, AeadAlgorithmTag.Gcm) };
            Cert cert = MakeCert(6, new[]{ SymmetricKeyAlgorithmTag.Camellia256 }, suites, BothFeatures);
            Assert.That(Select(cert).SymmetricAlgorithm, Is.EqualTo(SymmetricKeyAlgorithmTag.Camellia256));

            // a bit flipped in the direct-key signature (the second packet) of the certificate, and none at all
            byte[][] packets = PgpUnsupportedVersionTest.SplitPackets(cert.Public.GetEncoded());
            packets[1][packets[1].Length - 5] ^= 0x01;
            var corrupted = new PgpPublicKeyRing(packets.Aggregate(new byte[0], Arrays.Concatenate));
            Assert.Throws<ArgumentException>(() => PgpEncryptionPreferences.Select(new[]{ corrupted }));

            var stripped = new PgpPublicKeyRing(packets.Where((p, i) => i != 1).Aggregate(new byte[0],
                Arrays.Concatenate));
            Assert.Throws<ArgumentException>(() => PgpEncryptionPreferences.Select(new[]{ stripped }));

            // an expired direct-key signature
            var generator = new Ed25519KeyPairGenerator();
            generator.Init(new Ed25519KeyGenerationParameters(Random));
            var old = new PgpKeyPair(6, PublicKeyAlgorithmTag.Ed25519, generator.GenerateKeyPair(),
                DateTime.UtcNow.AddHours(-3));
            var hashed = new PgpSignatureSubpacketGenerator();
            hashed.SetSignatureCreationTime(false, DateTime.UtcNow.AddHours(-2));
            hashed.SetSignatureExpirationTime(false, 3600);
            hashed.SetIssuerFingerprint(false, old.PublicKey);
            var signer = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha256);
            signer.InitSign(PgpSignature.DirectKey, old.PrivateKey);
            signer.SetHashedSubpackets(hashed.Generate());
            var expired = new PgpPublicKeyRing(PgpPublicKey.AddCertification(old.PublicKey,
                signer.GenerateCertification(old.PublicKey)).GetEncoded());
            Assert.Throws<ArgumentException>(() => PgpEncryptionPreferences.Select(new[]{ expired }));

            // a revoked primary key
            PgpSecretKey secret = cert.Secret.GetSecretKey();
            var revoker = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha256);
            revoker.InitSign(PgpSignature.KeyRevocation, secret.ExtractPrivateKey(null));
            PgpPublicKey primary = cert.Public.GetPublicKey();
            var revoked = PgpPublicKeyRing.InsertPublicKey(cert.Public,
                PgpPublicKey.AddCertification(primary, revoker.GenerateCertification(primary)));
            Assert.Throws<ArgumentException>(() => PgpEncryptionPreferences.Select(new[]{ revoked }));
        }

        // RFC 9580 5.2.3.10: the newest valid self-signature of a user ID replaces the older ones, primary flag
        // included, and a revocation removes the user ID
        [Test]
        public void OnlyTheNewestSelfSignatureOfAUserIdCounts()
        {
            PgpKeyPair pair = EdDsaPair(4);
            DateTime now = DateTime.UtcNow.AddHours(-1);

            PgpSignature Sign(int type, string id, DateTime time, SymmetricKeyAlgorithmTag cipher, bool primary)
            {
                var hashed = new PgpSignatureSubpacketGenerator();
                hashed.SetSignatureCreationTime(false, time);
                hashed.SetPreferredSymmetricAlgorithms(false, new[]{ (int)cipher });
                if (primary)
                {
                    hashed.SetPrimaryUserId(false, true);
                }
                var signer = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha256);
                signer.InitSign(type, pair.PrivateKey);
                signer.SetHashedSubpackets(hashed.Generate());
                return signer.GenerateCertification(id, pair.PublicKey);
            }

            SymmetricKeyAlgorithmTag Preferred(PgpPublicKey certified) => PgpEncryptionPreferences.Select(new[]
            {
                new PgpPublicKeyRing(certified.GetEncoded()),
            }).SymmetricAlgorithm;

            // the old certification marks the user ID primary, the newer one does not
            PgpPublicKey key = PgpPublicKey.AddCertification(pair.PublicKey, "id", Sign(
                PgpSignature.PositiveCertification, "id", now.AddHours(-1), SymmetricKeyAlgorithmTag.Camellia256,
                true));
            Assert.That(Preferred(key), Is.EqualTo(SymmetricKeyAlgorithmTag.Camellia256));
            key = PgpPublicKey.AddCertification(key, "id", Sign(PgpSignature.PositiveCertification, "id", now,
                SymmetricKeyAlgorithmTag.Twofish, false));
            Assert.That(Preferred(key), Is.EqualTo(SymmetricKeyAlgorithmTag.Twofish));

            // a revoked primary user ID does not count; the other user ID does
            key = PgpPublicKey.AddCertification(key, "other", Sign(PgpSignature.PositiveCertification, "other",
                now.AddHours(-1), SymmetricKeyAlgorithmTag.Blowfish, false));
            key = PgpPublicKey.AddCertification(key, "id", Sign(PgpSignature.PositiveCertification, "id",
                now.AddMinutes(1), SymmetricKeyAlgorithmTag.Camellia192, true));
            Assert.That(Preferred(key), Is.EqualTo(SymmetricKeyAlgorithmTag.Camellia192));
            key = PgpPublicKey.AddCertification(key, "id", Sign(PgpSignature.CertificationRevocation, "id",
                now.AddMinutes(2), SymmetricKeyAlgorithmTag.Camellia128, false));
            Assert.That(Preferred(key), Is.EqualTo(SymmetricKeyAlgorithmTag.Blowfish));
        }

        // RFC 9580 5.2.3.10, 5.2.3.18: a self-signature that has expired, or is made in the future, is not valid
        [TestCase(4)]
        [TestCase(6)]
        public void OnlySelfSignaturesInEffectCount(int version)
        {
            PgpKeyPair pair = EdDsaPair(version);
            DateTime now = DateTime.UtcNow;
            int type = version == 6 ? PgpSignature.DirectKey : PgpSignature.PositiveCertification;

            PgpPublicKey Add(PgpPublicKey certified, DateTime time, SymmetricKeyAlgorithmTag cipher, long expiry)
            {
                var hashed = new PgpSignatureSubpacketGenerator();
                hashed.SetSignatureCreationTime(false, time);
                hashed.SetPreferredSymmetricAlgorithms(false, new[]{ (int)cipher });
                hashed.SetPreferredAeadCiphersuites(false, new[]{ Suite(cipher, AeadAlgorithmTag.Ocb) });
                if (expiry > 0)
                {
                    hashed.SetSignatureExpirationTime(false, expiry);
                }
                var signer = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha256);
                signer.InitSign(type, pair.PrivateKey);
                signer.SetHashedSubpackets(hashed.Generate());
                return version == 6
                    ? PgpPublicKey.AddCertification(certified, signer.GenerateCertification(pair.PublicKey))
                    : PgpPublicKey.AddCertification(certified, "id",
                        signer.GenerateCertification("id", pair.PublicKey));
            }

            SymmetricKeyAlgorithmTag Preferred(PgpPublicKey certified) => PgpEncryptionPreferences.Select(new[]
            {
                new PgpPublicKeyRing(certified.GetEncoded()),
            }).SymmetricAlgorithm;

            PgpPublicKey key = Add(pair.PublicKey, now.AddHours(-1), SymmetricKeyAlgorithmTag.Camellia256, 0);
            key = Add(key, now.AddMinutes(-30), SymmetricKeyAlgorithmTag.Twofish, 60);
            Assert.That(Preferred(key), Is.EqualTo(SymmetricKeyAlgorithmTag.Camellia256), "expired");
            key = Add(key, now.AddHours(1), SymmetricKeyAlgorithmTag.Blowfish, 0);
            Assert.That(Preferred(key), Is.EqualTo(SymmetricKeyAlgorithmTag.Camellia256), "future");
        }

        // RFC 9580 5.2.3.20: a non-revocable self-signature ignores later revocations
        [TestCase(false)]
        [TestCase(true)]
        public void NonRevocableSelfSignaturesIgnoreRevocations(bool revocable)
        {
            PgpKeyPair pair = EdDsaPair(4);
            DateTime now = DateTime.UtcNow;

            PgpSignature Sign(int type, DateTime time, bool isRevocable,
                SymmetricKeyAlgorithmTag cipher = SymmetricKeyAlgorithmTag.Camellia256)
            {
                var hashed = new PgpSignatureSubpacketGenerator();
                hashed.SetSignatureCreationTime(false, time);
                hashed.SetPreferredSymmetricAlgorithms(false, new[]{ (int)cipher });
                hashed.SetRevocable(false, isRevocable);
                var signer = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha256);
                signer.InitSign(type, pair.PrivateKey);
                signer.SetHashedSubpackets(hashed.Generate());
                return signer.GenerateCertification("id", pair.PublicKey);
            }

            SymmetricKeyAlgorithmTag Preferred(PgpPublicKey certified) => PgpEncryptionPreferences.Select(new[]
            {
                new PgpPublicKeyRing(certified.GetEncoded()),
            }).SymmetricAlgorithm;

            PgpPublicKey key = PgpPublicKey.AddCertification(pair.PublicKey, "id",
                Sign(PgpSignature.PositiveCertification, now.AddMinutes(-30), revocable));
            PgpPublicKey revoked = PgpPublicKey.AddCertification(key, "id",
                Sign(PgpSignature.CertificationRevocation, now.AddMinutes(-20), true));

            // without the user ID, there are no preferences, and AES-128 is implied
            SymmetricKeyAlgorithmTag expected = revocable
                ? SymmetricKeyAlgorithmTag.Aes128
                : SymmetricKeyAlgorithmTag.Camellia256;
            Assert.That(Preferred(revoked), Is.EqualTo(expected));

            // a newer revocable certification is revoked, and the non-revocable one applies again
            key = PgpPublicKey.AddCertification(key, "id", Sign(PgpSignature.PositiveCertification,
                now.AddMinutes(-25), true, SymmetricKeyAlgorithmTag.Twofish));
            key = PgpPublicKey.AddCertification(key, "id",
                Sign(PgpSignature.CertificationRevocation, now.AddMinutes(-20), true));
            Assert.That(Preferred(key), Is.EqualTo(expected));
        }

        // RFC 9580 5.12: a user attribute has self-signatures like a user ID
        [Test]
        public void PreferencesOfUserAttributes()
        {
            PgpKeyPair pair = EdDsaPair(4);
            var attributesGenerator = new PgpUserAttributeSubpacketVectorGenerator();
            attributesGenerator.SetImageAttribute(ImageAttrib.Format.Jpeg, new byte[]{ 0xFF, 0xD8, 0xFF, 0xD9 });
            PgpUserAttributeSubpacketVector attributes = attributesGenerator.Generate();

            var signer = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha256);
            signer.InitSign(PgpSignature.PositiveCertification, pair.PrivateKey);
            signer.SetHashedSubpackets(Packets(new[]{ SymmetricKeyAlgorithmTag.Camellia256 }, null, 0));
            PgpPublicKey key = PgpPublicKey.AddCertification(pair.PublicKey, attributes,
                signer.GenerateCertification(attributes, pair.PublicKey));

            Assert.That(PgpEncryptionPreferences.Select(new[]{ new PgpPublicKeyRing(key.GetEncoded()) })
                .SymmetricAlgorithm, Is.EqualTo(SymmetricKeyAlgorithmTag.Camellia256));
        }

        // The certificate of RFC 9580 A.3.
        [Test]
        public void Rfc9580Certificate()
        {
            var cert = new PgpPublicKeyRing(PgpV6TestUtilities.LoadRfc9580("a3-v6-certificate.asc"));
            PgpEncryptionPreferences result = PgpEncryptionPreferences.Select(new[]{ cert });

            // its direct-key signature lists AES-256 and AES-128 with OCB, and announces SEIPD v2
            Assert.That(result.UseSeipdV2, Is.True);
            Assert.That(result.SymmetricAlgorithm, Is.EqualTo(SymmetricKeyAlgorithmTag.Aes256));
            Assert.That(result.AeadAlgorithm, Is.EqualTo(AeadAlgorithmTag.Ocb));
        }

        [Test]
        public void PrimaryUserIdOfVersion4Certificates()
        {
            PgpKeyPair pair = EdDsaPair(4);
            var generator = new PgpKeyRingGenerator(pair, HashAlgorithmTag.Sha256, Packets(null, null, 0), null,
                PgpSecretKeyProtection.None, Random);
            generator.AddUserId("primary", PgpSignature.PositiveCertification,
                Packets(new[]{ SymmetricKeyAlgorithmTag.Camellia256 }, null, 0, primary: true), null);
            generator.AddUserId("newer", PgpSignature.PositiveCertification,
                Packets(new[]{ SymmetricKeyAlgorithmTag.Twofish }, null, 0), null);

            var cert = new PgpPublicKeyRing(generator.GeneratePublicKeyRing().GetEncoded());
            Assert.That(PgpEncryptionPreferences.Select(new[]{ cert }).SymmetricAlgorithm,
                Is.EqualTo(SymmetricKeyAlgorithmTag.Camellia256));

            // without a certification, the direct-key signature is used
            generator = new PgpKeyRingGenerator(EdDsaPair(4), HashAlgorithmTag.Sha256,
                Packets(new[]{ SymmetricKeyAlgorithmTag.Twofish }, null, 0), null, PgpSecretKeyProtection.None, Random);
            cert = new PgpPublicKeyRing(generator.GeneratePublicKeyRing().GetEncoded());
            Assert.That(PgpEncryptionPreferences.Select(new[]{ cert }).SymmetricAlgorithm,
                Is.EqualTo(SymmetricKeyAlgorithmTag.Twofish));
        }

        [Test]
        public void UserIdsWithOtherThanAsciiCharacters()
        {
            var generator = new PgpKeyRingGenerator(EdDsaPair(4), HashAlgorithmTag.Sha256, Packets(null, null, 0),
                null, PgpSecretKeyProtection.None, Random);
            generator.AddUserId("Ricarda S. Álvarez", PgpSignature.PositiveCertification,
                Packets(new[]{ SymmetricKeyAlgorithmTag.Camellia256 }, null, 0), null);

            var cert = new PgpPublicKeyRing(generator.GeneratePublicKeyRing().GetEncoded());
            Assert.That(PgpEncryptionPreferences.Select(new[]{ cert }).SymmetricAlgorithm,
                Is.EqualTo(SymmetricKeyAlgorithmTag.Camellia256));
        }

        [Test]
        public void AesOnlyForRecipientsWithXdhAndKemKeys()
        {
            var camelliaFirst = new[]{ SymmetricKeyAlgorithmTag.Camellia256, SymmetricKeyAlgorithmTag.Aes192 };

            Cert xdh = MakeCert(4, camelliaFirst, null, FeatureMdc);
            PgpEncryptionPreferences result = Select(xdh);
            Assert.That(result.UseSeipdV2, Is.False);
            Assert.That(result.SymmetricAlgorithm, Is.EqualTo(SymmetricKeyAlgorithmTag.Aes192));
            Assert.That(Decrypt(Encrypt(result, xdh), xdh), Is.EqualTo(Content));

            // a certificate that does not use these algorithms may get Camellia
            Cert ecdh = MakeCert(4, camelliaFirst, null, FeatureMdc, xdh: false);
            Assert.That(Select(ecdh).SymmetricAlgorithm, Is.EqualTo(SymmetricKeyAlgorithmTag.Camellia256));
        }

        /// <summary>Without certificates there is nothing to choose from.</summary>
        [Test]
        public void NoCertificates()
        {
            Assert.Throws<ArgumentException>(() => PgpEncryptionPreferences.Select(new PgpPublicKeyRing[0]));
            Assert.Throws<ArgumentNullException>(() => PgpEncryptionPreferences.Select(null));
        }
    }
}
