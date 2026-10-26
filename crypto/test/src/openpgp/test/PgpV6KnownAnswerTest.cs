using System;
using System.IO;
using System.Linq;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    /// <summary>
    /// Known-answer tests for the generation side: with the random inputs of the RFC 9580 and RFC 9980 test vectors
    /// the code reproduces the packets of the vectors.
    /// </summary>
    [TestFixture]
    public class PgpV6KnownAnswerTest
    {
        private static FixedSecureRandom Fixed(params string[] hexValues) => new FixedSecureRandom(
            hexValues.Select(h => (FixedSecureRandom.Source)new FixedSecureRandom.Data(Hex.Decode(h))).ToArray());

        /// <summary>The body of the first packet of a message, without the header.</summary>
        private static byte[] PacketBody(byte[] packet)
        {
            int headerLength;
            int first = packet[1];
            if (first < 192)
            {
                headerLength = 2;
            }
            else if (first < 224)
            {
                headerLength = 3;
            }
            else if (first == 255)
            {
                headerLength = 6;
            }
            else
            {
                throw new ArgumentException("partial length");
            }
            return Arrays.CopyOfRange(packet, headerLength, packet.Length);
        }

        // Encrypting the session key of A.8 with the ephemeral secret of the vector.
        [Test]
        public void X25519SessionKeyEncryption()
        {
            var certificate = new PgpPublicKeyRing(PgpV6TestUtilities.LoadRfc9580("a3-v6-certificate.asc"));
            PgpPublicKey subkey = certificate.GetPublicKeys().Last();
            var recipient = (X25519PublicKeyParameters)subkey.GetKey();
            Assert.That(Hex.ToHexString(recipient.GetEncoded()), Is.EqualTo(
                "8693248367f9e5015db922f8f48095dda784987f2d5985b12fbad16caf5e4435"));

            var ephemeralSecret = new X25519PrivateKeyParameters(
                Hex.Decode("af1e43c0d123efe893a7d4d390f3a761e3fac33dfc7f3edaa830c9011352c779"));
            Assert.That(Hex.ToHexString(ephemeralSecret.GeneratePublicKey().GetEncoded()), Is.EqualTo(
                "87cf18d5f1b53f817cce5a004cf393cc8958bddc065f25f84af509b17dd36764"));

            // the shared point and the key-encryption key of the vector
            byte[] shared = new byte[32];
            ephemeralSecret.GenerateSecret(recipient, shared, 0);
            Assert.That(Hex.ToHexString(shared), Is.EqualTo(
                "67e30e69cdc7bab2a2680d78aca46a2f8b6e2ae44d398bdc6f92c5ad4a492514"));

            byte[] ikm = Arrays.ConcatenateAll(ephemeralSecret.GeneratePublicKey().GetEncoded(), recipient.GetEncoded(),
                shared);
            byte[] kek = PgpAead.Hkdf(new Sha256Digest(), ikm, null, Strings.ToUtf8ByteArray("OpenPGP X25519"), 16);
            Assert.That(Hex.ToHexString(kek), Is.EqualTo("f66dadcff64592239b254539b64ff607"));

            // the PKESK fields (ephemeral key, length, wrapped session key) of the vector
            byte[] sessionKey = Hex.Decode("dd708f6fa1ed65114d68d2343e7c2f1d");
            var ephemeral = new AsymmetricCipherKeyPair(ephemeralSecret.GeneratePublicKey(), ephemeralSecret);
            byte[] fields = PgpXdhKem.X25519.Encrypt(recipient, ephemeral, sessionKey, isVersion3Pkesk: false,
                SymmetricKeyAlgorithmTag.Aes128, new SecureRandom());

            var vector = (PublicKeyEncSessionPacket)BcpgInputStream.Wrap(new MemoryStream(
                PgpV6TestUtilities.LoadRfc9580("a8-x25519-ocb-message.asc"), false)).ReadPacket();
            Assert.That(fields, Is.EqualTo(vector.GetEncSessionKey()[0]));

            // and the packet around them
            PublicKeyEncSessionPacket packet = PublicKeyEncSessionPacket.CreateV6Packet(6, subkey.GetFingerprint(),
                PublicKeyAlgorithmTag.X25519, new[]{ fields });
            Assert.That(packet.GetEncoded(), Is.EqualTo(
                Arrays.CopyOf(PgpV6TestUtilities.LoadRfc9580("a8-x25519-ocb-message.asc"), packet.GetEncoded().Length)));
        }

        private sealed class AeadVector
        {
            internal string File;
            internal AeadAlgorithmTag Aead;
            internal string DerivedKey, SkeskHkdf, SessionKey, MessageKey, Iv, Padding;
        }

        private static readonly AeadVector[] AeadVectors =
        {
            new AeadVector
            {
                File = "a9-eax-message.asc", Aead = AeadAlgorithmTag.Eax,
                DerivedKey = "154967e590aa1f923e1c0ac64c88f23d", SkeskHkdf = "2fce331f39dd955cc41e95d870c72139",
                SessionKey = "3881bafe985412459b86c36f98cb9a5e", MessageKey = "b50422ac1c26be9ddd831d5bbb36b64f",
                Iv = "78b833f2e94a60c0", Padding = "d50eae5bf0cd6705500355816cb0c8ff",
            },
            new AeadVector
            {
                File = "a10-ocb-message.asc", Aead = AeadAlgorithmTag.Ocb,
                DerivedKey = "e80de243a362d93b9dc607ede96a7356", SkeskHkdf = "38a9b345b5680bb61bb65d73eec7ecd9",
                SessionKey = "28e79ab82397d3c63de24ac217d7b791", MessageKey = "71662a11ee5b4e08144e6de883a00999",
                Iv = "ebde12bb570dcf", Padding = "d50eae6aa1649b56aa835b2613902bd2",
            },
            new AeadVector
            {
                File = "a11-gcm-message.asc", Aead = AeadAlgorithmTag.Gcm,
                DerivedKey = "250281715bba7828ef71ef64c4784753", SkeskHkdf = "7a6f9ab7f99f7ef8dbef841c650800f5",
                SessionKey = "1936fc8568980274bb900d8319360c77", MessageKey = "ea1438803cb8a47740ce9b54c338778d",
                Iv = "4d2bdc2b", Padding = "d50e1ce2269a9eddef81032172b7ed7c",
            },
        };

        private const string LiteralPacket = "cb1362000000000048656c6c6f2c20776f726c6421";

        // The SEIPD v2 packets of A.9, A.10 and A.11.
        [Test]
        public void Seipd2PacketsAreReproduced()
        {
            foreach (AeadVector vector in AeadVectors)
            {
                byte[] message = PgpV6TestUtilities.LoadRfc9580(vector.File);
                byte[][] packets = PgpUnsupportedVersionTest.SplitPackets(message);
                byte[] seipd = PacketBody(packets[1]);

                // 02 | cipher | aead | chunk size octet | salt (32)
                Assert.That(seipd[0], Is.EqualTo(2));
                var cipher = (SymmetricKeyAlgorithmTag)seipd[1];
                var aead = (AeadAlgorithmTag)seipd[2];
                int chunkSizeOctet = seipd[3];
                byte[] salt = Arrays.CopyOfRange(seipd, 4, 36);
                Assert.That(aead, Is.EqualTo(vector.Aead), vector.File);

                byte[] aad = { 0xD2, 0x02, (byte)cipher, (byte)aead, (byte)chunkSizeOctet };
                byte[][] keyAndIv = PgpAead.DeriveMessageKeyAndIv(cipher, aead, Hex.Decode(vector.SessionKey), salt,
                    aad);
                Assert.That(Hex.ToHexString(keyAndIv[0]), Is.EqualTo(vector.MessageKey), vector.File);
                Assert.That(Hex.ToHexString(keyAndIv[1], 0, vector.Iv.Length / 2), Is.EqualTo(vector.Iv), vector.File);

                var output = new MemoryStream();
                output.Write(seipd, 0, 36);
                var stream = new PgpAeadOutputStream(output, cipher, aead, keyAndIv[0], keyAndIv[1], aad,
                    chunkSizeOctet);
                byte[] plaintext = Hex.Decode(LiteralPacket + vector.Padding);
                stream.Write(plaintext, 0, plaintext.Length);
                stream.Finish();

                Assert.That(output.ToArray(), Is.EqualTo(seipd), vector.File);
            }
        }

        // The SKESK packets of A.9, A.10 and A.11.
        [Test]
        public void Skesk6PacketsAreReproduced()
        {
            byte[] passPhrase = Strings.ToUtf8ByteArray("password");

            foreach (AeadVector vector in AeadVectors)
            {
                byte[] message = PgpV6TestUtilities.LoadRfc9580(vector.File);
                byte[][] packets = PgpUnsupportedVersionTest.SplitPackets(message);
                var skesk = (SymmetricKeyEncSessionPacket)BcpgInputStream.Wrap(new MemoryStream(packets[0], false))
                    .ReadPacket();
                Assert.That(skesk.Version, Is.EqualTo(6));

                byte[] derived = PgpUtilities.DoMakeKeyFromPassPhrase(skesk.EncAlgorithm, skesk.S2k, passPhrase,
                    clearPassPhrase: false).GetKey();
                Assert.That(Hex.ToHexString(derived), Is.EqualTo(vector.DerivedKey), vector.File);

                byte[] aad = skesk.GetAAData();
                byte[] kek = PgpAead.Hkdf(derived, null, aad, 16);
                Assert.That(Hex.ToHexString(kek), Is.EqualTo(vector.SkeskHkdf), vector.File);

                byte[] encrypted = PgpAead.EncryptOneShot(skesk.EncAlgorithm, skesk.AeadAlgorithm, kek, skesk.GetIV(),
                    aad, Hex.Decode(vector.SessionKey));
                Assert.That(Arrays.CopyOfRange(encrypted, 0, 16), Is.EqualTo(skesk.GetSecKeyData()), vector.File);
                Assert.That(Arrays.CopyOfRange(encrypted, 16, encrypted.Length), Is.EqualTo(skesk.GetAuthTag()));

                SymmetricKeyEncSessionPacket rebuilt = SymmetricKeyEncSessionPacket.CreateV6Packet(skesk.EncAlgorithm,
                    skesk.AeadAlgorithm, skesk.GetIV(), skesk.S2k, Arrays.CopyOfRange(encrypted, 0, 16),
                    Arrays.CopyOfRange(encrypted, 16, encrypted.Length));
                Assert.That(rebuilt.GetEncoded(), Is.EqualTo(packets[0]), vector.File);
            }
        }

        // Locking the key of A.4 with the Argon2 salt and AEAD nonce of A.5.
        [Test, Category("Slow")]
        public void LockedSecretKeyIsReproduced()
        {
            var locked = new PgpSecretKeyRing(PgpV6TestUtilities.LoadRfc9580("a5-v6-locked-secret-key.asc"));
            var unlocked = new PgpSecretKeyRing(PgpV6TestUtilities.LoadRfc9580("a4-v6-secret-key.asc"));
            byte[] passPhrase = Strings.ToUtf8ByteArray("correct horse battery staple");

            PgpSecretKey[] lockedKeys = locked.GetSecretKeys().ToArray();
            PgpSecretKey[] unlockedKeys = unlocked.GetSecretKeys().ToArray();

            // the Argon2 settings of the vector need 2 GiB: skip on machines that cannot provide the memory
            try
            {
                for (int i = 0; i < lockedKeys.Length; ++i)
                {
                    var packet = (SecretKeyPacket)BcpgInputStream.Wrap(
                        new MemoryStream(lockedKeys[i].GetEncoded(), false)).ReadPacket();
                    Assert.That(packet.S2kUsage, Is.EqualTo(SecretKeyPacket.UsageAead));
                    Assert.That(packet.S2k.Type, Is.EqualTo(S2k.Argon2));

                    S2k.Argon2Params argon2 = packet.S2k.Argon2Config;
                    var template = new S2k.Argon2Params(argon2.GetSalt(), argon2.Passes, argon2.Parallelism,
                        argon2.MemorySizeExponent);

                    var protection = PgpSecretKeyProtection.AeadArgon2(packet.EncAlgorithm, packet.AeadAlgorithm,
                        template, passPhrase);

                    // the salt is drawn first, then the nonce
                    PgpSecretKey relocked = PgpSecretKey.CopyWithNewProtection(unlockedKeys[i], new byte[0], protection,
                        Fixed(Hex.ToHexString(argon2.GetSalt()), Hex.ToHexString(packet.GetIV())));

                    Assert.That(relocked.GetEncoded(), Is.EqualTo(lockedKeys[i].GetEncoded()), "key " + i);
                }
            }
            catch (OutOfMemoryException)
            {
                Assert.Ignore("Argon2 with 2 GiB of memory is not available");
            }
        }

        private static PgpSignature Regenerate(PgpSignature original, PgpPrivateKey signer, PgpPublicKey primary,
            PgpPublicKey target, string userId)
        {
            var generator = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, original.HashAlgorithm);
            generator.InitSign(original.SignatureType, signer, Fixed(Hex.ToHexString(original.GetSalt())));
            generator.SetHashedSubpackets(original.GetHashedSubPackets());
            generator.SetUnhashedSubpackets(original.GetUnhashedSubPackets());

            if (userId != null)
                return generator.GenerateCertification(userId, primary);
            if (target == null)
                return generator.GenerateCertification(primary);

            return generator.GenerateCertification(primary, target);
        }

        // The self-signatures of RFC 9580 A.3 and RFC 9980 A.1 are regenerated exactly.
        [Test]
        public void SelfSignaturesAreReproduced()
        {
            var sources = new[]
            {
                new[]{ PgpV6TestUtilities.LoadRfc9580("a3-v6-certificate.asc"),
                    PgpV6TestUtilities.LoadRfc9580("a4-v6-secret-key.asc") },
                new[]{ PgpV6TestUtilities.LoadRfc9980("a1-public-key.asc"),
                    PgpV6TestUtilities.LoadRfc9980("a1-secret-key.asc") },
            };

            int reproduced = 0;
            foreach (byte[][] source in sources)
            {
                var publicRing = new PgpPublicKeyRing(source[0]);
                var secretRing = new PgpSecretKeyRing(source[1]);
                PgpPublicKey primary = publicRing.GetPublicKey();
                PgpPrivateKey signer = secretRing.GetSecretKey().ExtractPrivateKey(new char[0]);

                foreach (PgpSignature original in primary.GetKeySignatures())
                {
                    Assert.That(Regenerate(original, signer, primary, null, null).GetEncoded(),
                        Is.EqualTo(original.GetEncoded()), "direct key signature");
                    ++reproduced;
                }

                foreach (string id in primary.GetUserIds())
                {
                    foreach (PgpSignature original in primary.GetSignaturesForId(id))
                    {
                        Assert.That(Regenerate(original, signer, primary, null, id).GetEncoded(),
                            Is.EqualTo(original.GetEncoded()), "certification of " + id);
                        ++reproduced;
                    }
                }

                foreach (PgpPublicKey subkey in publicRing.GetPublicKeys().Skip(1))
                {
                    foreach (PgpSignature original in subkey.GetSignaturesOfType(PgpSignature.SubkeyBinding))
                    {
                        Assert.That(Regenerate(original, signer, primary, subkey, null).GetEncoded(),
                            Is.EqualTo(original.GetEncoded()), "subkey binding");
                        ++reproduced;
                    }
                }
            }

            Assert.That(reproduced, Is.GreaterThanOrEqualTo(4));
        }
    }
}
