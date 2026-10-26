using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    /// <summary>Tests for version 6 PKESK packets with version 2 SEIPD packets (RFC 9580 5.1.2, 5.13.2).</summary>
    [TestFixture]
    public class PgpV6PkeskTest
    {
        private static readonly SecureRandom Random = new SecureRandom();

        private static readonly byte[] Content = Strings.ToUtf8ByteArray("a message for version 6 PKESK packets");

        internal sealed class Recipient
        {
            internal string Name;
            internal PgpPublicKey PublicKey;
            internal PgpPrivateKey PrivateKey;

            public override string ToString() => Name;
        }

        private static PgpPrivateKey SecretSubkey(PgpSecretKeyRing ring, PublicKeyAlgorithmTag algorithm) =>
            ring.GetSecretKeys().First(k => !k.IsMasterKey && k.PublicKey.Algorithm == algorithm)
                .ExtractPrivateKey(new char[0]);

        private static PgpPublicKey PublicSubkey(PgpPublicKeyRing ring, PublicKeyAlgorithmTag algorithm) =>
            ring.GetPublicKeys().First(k => !k.IsMasterKey && k.Algorithm == algorithm);

        private static Recipient FromRfcRing(string name, PgpPublicKeyRing publicRing, PgpSecretKeyRing secretRing,
            PublicKeyAlgorithmTag algorithm)
        {
            return new Recipient
            {
                Name = name,
                PublicKey = PublicSubkey(publicRing, algorithm),
                PrivateKey = SecretSubkey(secretRing, algorithm),
            };
        }

        /// <summary>The keys of RFC 9580 A.4, RFC 9980 A.1 and A.2: version 6 and version 4 keys.</summary>
        internal static Recipient[] RfcRecipients() => new[]
        {
            FromRfcRing("X25519, v6 (RFC 9580 A.4)",
                new PgpPublicKeyRing(PgpV6TestUtilities.LoadRfc9580("a3-v6-certificate.asc")),
                new PgpSecretKeyRing(PgpV6TestUtilities.LoadRfc9580("a4-v6-secret-key.asc")),
                PublicKeyAlgorithmTag.X25519),
            FromRfcRing("ML-KEM-768+X25519, v6 (RFC 9980 A.1)",
                new PgpPublicKeyRing(PgpV6TestUtilities.LoadRfc9980("a1-public-key.asc")),
                new PgpSecretKeyRing(PgpV6TestUtilities.LoadRfc9980("a1-secret-key.asc")),
                PublicKeyAlgorithmTag.MLKem768_X25519),
            FromRfcRing("ML-KEM-768+X25519, v4 (RFC 9980 A.2)", PgpMLKemX25519Test.A2PublicRing(),
                PgpMLKemX25519Test.A2SecretRing(), PublicKeyAlgorithmTag.MLKem768_X25519),
        };

        internal static Recipient[] GeneratedRecipients()
        {
            var recipients = new List<Recipient>();

            // RSA
            PgpSecretKeyRing rsaSecret = PgpUnsupportedVersionTest.GenerateRsaRing(out PgpPublicKeyRing rsaPublic);
            recipients.Add(new Recipient
            {
                Name = "RSA, v4",
                PublicKey = rsaPublic.GetPublicKey(),
                PrivateKey = rsaSecret.GetSecretKey().ExtractPrivateKey(new char[0]),
            });

            // ECDH over NIST P-256 and legacy Curve25519
            var ecGen = new ECKeyPairGenerator();
            ecGen.Init(new ECKeyGenerationParameters(SecObjectIdentifiers.SecP256r1, Random));
            var ecdh = new PgpKeyPair(PublicKeyAlgorithmTag.ECDH, ecGen.GenerateKeyPair(), DateTime.UtcNow);
            recipients.Add(new Recipient{ Name = "ECDH P-256, v4", PublicKey = ecdh.PublicKey,
                PrivateKey = ecdh.PrivateKey });

            var x25519Gen = new X25519KeyPairGenerator();
            x25519Gen.Init(new X25519KeyGenerationParameters(Random));
            var legacy = new PgpKeyPair(PublicKeyAlgorithmTag.ECDH, x25519Gen.GenerateKeyPair(), DateTime.UtcNow);
            recipients.Add(new Recipient{ Name = "ECDH Curve25519Legacy, v4", PublicKey = legacy.PublicKey,
                PrivateKey = legacy.PrivateKey });

            // X25519 and X448 keys of version 4
            foreach (var algorithm in new[]{ PublicKeyAlgorithmTag.X25519, PublicKeyAlgorithmTag.X448 })
            {
                PgpKeyPair pair = PgpXdhEncryptionTest.NewSubkeyPair(algorithm);
                recipients.Add(new Recipient{ Name = algorithm + ", v4", PublicKey = pair.PublicKey,
                    PrivateKey = pair.PrivateKey });
            }

            // keys of version 6
            var rsa6 = new PgpKeyPair(6, PublicKeyAlgorithmTag.RsaGeneral, PgpV6KeyGenerationTest.GenerateRsa(),
                DateTime.UtcNow);
            recipients.Add(new Recipient{ Name = "RSA, v6", PublicKey = rsa6.PublicKey, PrivateKey = rsa6.PrivateKey });

            foreach (var curve in new[]
            {
                SecObjectIdentifiers.SecP256r1, SecObjectIdentifiers.SecP384r1, SecObjectIdentifiers.SecP521r1,
                Org.BouncyCastle.Asn1.TeleTrust.TeleTrusTObjectIdentifiers.BrainpoolP256R1,
            })
            {
                var pair = new PgpKeyPair(6, PublicKeyAlgorithmTag.ECDH, PgpV6KeyGenerationTest.GenerateEc(curve),
                    DateTime.UtcNow);
                recipients.Add(new Recipient{ Name = "ECDH " + curve + ", v6", PublicKey = pair.PublicKey,
                    PrivateKey = pair.PrivateKey });
            }

            foreach (var algorithm in new[]{ PublicKeyAlgorithmTag.X25519, PublicKeyAlgorithmTag.X448 })
            {
                var pair = new PgpKeyPair(6, algorithm, PgpV6KeyGenerationTest.GenerateX(algorithm), DateTime.UtcNow);
                recipients.Add(new Recipient{ Name = algorithm + ", v6", PublicKey = pair.PublicKey,
                    PrivateKey = pair.PrivateKey });
            }

            return recipients.ToArray();
        }

        private static IEnumerable<Recipient> AllRecipients() => RfcRecipients().Concat(GeneratedRecipients());

        private static readonly object[][] Combinations =
        {
            new object[]{ SymmetricKeyAlgorithmTag.Aes256, AeadAlgorithmTag.Ocb },
            new object[]{ SymmetricKeyAlgorithmTag.Aes128, AeadAlgorithmTag.Eax },
            new object[]{ SymmetricKeyAlgorithmTag.Camellia192, AeadAlgorithmTag.Gcm },
        };

        internal static byte[] EncryptV2(IEnumerable<PgpPublicKey> recipients, byte[] content,
            SymmetricKeyAlgorithmTag cipher = SymmetricKeyAlgorithmTag.Aes256,
            AeadAlgorithmTag aead = AeadAlgorithmTag.Ocb, char[] passPhrase = null, int chunkSizeOctet = 6)
        {
            var generator = new PgpEncryptedDataGenerator(cipher, aead, chunkSizeOctet, Random);
            foreach (PgpPublicKey recipient in recipients)
            {
                generator.AddMethod(recipient);
            }
            if (passPhrase != null)
            {
                generator.AddMethod(passPhrase, HashAlgorithmTag.Sha256);
            }

            var bOut = new MemoryStream();
            using (Stream encOut = generator.Open(bOut, new byte[1 << 9]))
            using (Stream literal = new PgpLiteralDataGenerator().Open(encOut, PgpLiteralData.Binary, "",
                DateTime.UtcNow, new byte[1 << 9]))
            {
                literal.Write(content, 0, content.Length);
            }
            return bOut.ToArray();
        }

        [Test]
        public void EncryptAndDecryptForEveryAlgorithm()
        {
            foreach (Recipient recipient in AllRecipients())
            {
                foreach (object[] combination in Combinations)
                {
                    var cipher = (SymmetricKeyAlgorithmTag)combination[0];
                    var aead = (AeadAlgorithmTag)combination[1];

                    byte[] message = EncryptV2(new[]{ recipient.PublicKey }, Content, cipher, aead);

                    // a version 6 PKESK that names the key by version and fingerprint, then a version 2 SEIPD
                    var list = (PgpEncryptedDataList)new PgpObjectFactory(message).NextPgpObject();
                    Assert.That(list.Count, Is.EqualTo(1), recipient.Name);
                    var encData = (PgpPublicKeyEncryptedData)list[0];
                    Assert.That(encData.Version, Is.EqualTo(6), recipient.Name);
                    Assert.That(encData.KeyVersion, Is.EqualTo(recipient.PublicKey.Version), recipient.Name);
                    Assert.That(encData.GetKeyFingerprint(), Is.EqualTo(recipient.PublicKey.GetFingerprint()));
                    Assert.That(encData.KeyId, Is.EqualTo(recipient.PublicKey.KeyId));
                    Assert.That(encData.IsAead, Is.True);

                    PgpMLKemX25519Test.Decrypted result = PgpMLKemX25519Test.Decrypt(message, recipient.PrivateKey);
                    Assert.That(result.Content, Is.EqualTo(Content), recipient.Name);
                    Assert.That(result.IntegrityVerified, Is.True, recipient.Name);
                    Assert.That(result.Algorithm, Is.EqualTo(cipher));
                }
            }
        }

        [Test]
        public void MixedRecipientsOfAllKindsDecrypt()
        {
            Recipient[] recipients = AllRecipients().ToArray();
            char[] passPhrase = "pass phrase".ToCharArray();

            byte[] message = EncryptV2(recipients.Select(r => r.PublicKey), Content, passPhrase: passPhrase);

            var list = (PgpEncryptedDataList)new PgpObjectFactory(message).NextPgpObject();
            Assert.That(list.Count, Is.EqualTo(recipients.Length + 1));

            foreach (Recipient recipient in recipients)
            {
                PgpMLKemX25519Test.Decrypted result = PgpMLKemX25519Test.Decrypt(message, recipient.PrivateKey);
                Assert.That(result.Content, Is.EqualTo(Content), recipient.Name);
            }

            var pbe = list.GetEncryptedDataObjects().OfType<PgpPbeEncryptedData>().Single();
            using (Stream stream = pbe.GetDataStream(passPhrase))
            {
                var literal = (PgpLiteralData)new PgpObjectFactory(stream).NextPgpObject();
                Assert.That(Streams.ReadAll(literal.GetDataStream()), Is.EqualTo(Content));
                Assert.That(pbe.Verify(), Is.True);
            }
        }

        private static byte[] ReadLiteral(Stream decrypted)
        {
            using (decrypted)
            {
                var literal = (PgpLiteralData)new PgpObjectFactory(decrypted).NextPgpObject();
                return Streams.ReadAll(literal.GetDataStream());
            }
        }

        [Test]
        public void TwoPassPhrasesAndAPublicKey()
        {
            Recipient recipient = RfcRecipients()[0];
            char[] first = "first".ToCharArray(), second = "second".ToCharArray();

            var generator = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, AeadAlgorithmTag.Ocb, Random);
            generator.AddMethod(first, HashAlgorithmTag.Sha256);
            generator.AddMethod(recipient.PublicKey);
            generator.AddMethod(second, new S2k.Argon2Params(1, 1, 10, Random));

            var bOut = new MemoryStream();
            byte[] literalPacket = PgpV6TestUtilities.NewFormatPacket(PacketTag.LiteralData,
                Arrays.ConcatenateAll(new byte[]{ (byte)PgpLiteralData.Binary, 0, 0, 0, 0, 0 }, Content));
            using (Stream encOut = generator.Open(bOut, literalPacket.Length))
            {
                encOut.Write(literalPacket, 0, literalPacket.Length);
            }

            var list = (PgpEncryptedDataList)new PgpObjectFactory(bOut.ToArray()).NextPgpObject();
            Assert.That(list.Count, Is.EqualTo(3));

            var pbes = list.GetEncryptedDataObjects().OfType<PgpPbeEncryptedData>().ToArray();
            Assert.That(pbes.Length, Is.EqualTo(2));
            Assert.That(pbes.All(p => p.Version == 6), Is.True);

            // the encrypted data can only be read once, so use a fresh parse for each method
            PgpPbeEncryptedData Pbe(int index) => ((PgpEncryptedDataList)new PgpObjectFactory(bOut.ToArray())
                .NextPgpObject()).GetEncryptedDataObjects().OfType<PgpPbeEncryptedData>().ElementAt(index);

            Assert.That(ReadLiteral(Pbe(0).GetDataStream(first)), Is.EqualTo(Content));
            Assert.That(ReadLiteral(Pbe(1).GetDataStream(second)), Is.EqualTo(Content));

            Assert.That(PgpMLKemX25519Test.Decrypt(bOut.ToArray(), recipient.PrivateKey).Content, Is.EqualTo(Content));
        }

        [Test]
        public void ElGamalIsRefused()
        {
            var p = Org.BouncyCastle.Math.BigInteger.ProbablePrime(512, Random);
            var gen = new ElGamalKeyPairGenerator();
            gen.Init(new ElGamalKeyGenerationParameters(Random,
                new ElGamalParameters(p, Org.BouncyCastle.Math.BigInteger.Two)));
            PgpPublicKey elGamal = new PgpKeyPair(PublicKeyAlgorithmTag.ElGamalEncrypt, gen.GenerateKeyPair(),
                DateTime.UtcNow).PublicKey;

            var generator = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, AeadAlgorithmTag.Ocb, Random);
            Assert.Throws<PgpException>(() => generator.AddMethod(elGamal));
        }

        private static byte[] SinglePkeskMessage(byte[] message, Func<byte[], byte[]> mutateFields)
        {
            byte[][] packets = PgpUnsupportedVersionTest.SplitPackets(message);
            var pkesk = PgpV6TestUtilities.ReadPacket<PublicKeyEncSessionPacket>(packets[0]);
            byte[][] fields = pkesk.GetEncSessionKey();
            var modified = PublicKeyEncSessionPacket.CreateV6Packet(pkesk.KeyVersion, pkesk.GetKeyFingerprint(),
                pkesk.Algorithm, new[]{ mutateFields(fields[0]) });
            return Arrays.Concatenate(modified.GetEncoded(PacketFormat.Current),
                Arrays.ConcatenateAll(packets.Skip(1).ToArray()));
        }

        [Test]
        public void FailuresAreReportedUniformly()
        {
            foreach (Recipient recipient in AllRecipients().Where(r => r.PublicKey.Algorithm != PublicKeyAlgorithmTag.ECDH
                && r.PublicKey.Algorithm != PublicKeyAlgorithmTag.RsaGeneral))
            {
                byte[] message = EncryptV2(new[]{ recipient.PublicKey }, Content);
                var messages = new HashSet<string>();

                // flip octets of the algorithm-specific fields
                int length = PgpV6TestUtilities.ReadPacket<PublicKeyEncSessionPacket>(
                    PgpUnsupportedVersionTest.SplitPackets(message)[0]).GetEncSessionKey()[0].Length;
                foreach (int position in new[]{ 0, 1, length / 2, length - 9, length - 1 })
                {
                    byte[] modified = SinglePkeskMessage(message, f =>
                    {
                        byte[] copy = Arrays.Clone(f);
                        copy[position] ^= 0x01;
                        return copy;
                    });

                    var e = Assert.Throws<PgpException>(() =>
                        PgpMLKemX25519Test.FindEncryptedData(modified, recipient.PrivateKey.KeyId)
                            .GetDataStream(recipient.PrivateKey), recipient.Name + " " + position);
                    messages.Add(e.Message);
                }

                // truncated and extended fields
                foreach (var mutate in new Func<byte[], byte[]>[]
                {
                    f => Arrays.CopyOfRange(f, 0, f.Length - 1),
                    f => Arrays.Concatenate(f, new byte[]{ 0 }),
                    f => new byte[0],
                })
                {
                    byte[] modified = SinglePkeskMessage(message, mutate);
                    var e = Assert.Throws<PgpException>(() =>
                        PgpMLKemX25519Test.FindEncryptedData(modified, recipient.PrivateKey.KeyId)
                            .GetDataStream(recipient.PrivateKey), recipient.Name);
                    messages.Add(e.Message);
                }

                Assert.That(messages.Count, Is.EqualTo(1), recipient.Name + ": " + string.Join("; ", messages));
            }
        }

        [Test]
        public void SessionKeyLengthMustMatchTheSeipdCipher()
        {
            Recipient recipient = RfcRecipients()[0];

            // wrap a 16-octet key, but let the SEIPD packet use AES-256
            byte[] shortKey = new byte[16];
            Random.NextBytes(shortKey);
            byte[] fields = PgpXdhKem.X25519.Encrypt(recipient.PublicKey.GetKey(), shortKey, isVersion3Pkesk: false,
                SymmetricKeyAlgorithmTag.Aes128, Random);
            byte[] pkesk = PublicKeyEncSessionPacket.CreateV6Packet(6, recipient.PublicKey.GetFingerprint(),
                PublicKeyAlgorithmTag.X25519, new[]{ fields }).GetEncoded(PacketFormat.Current);

            byte[] seipd = PgpAeadStreamTest.EncryptSeipd(SymmetricKeyAlgorithmTag.Aes256, AeadAlgorithmTag.Ocb, 0,
                new byte[32], new byte[32], Content);
            byte[] message = Arrays.Concatenate(pkesk, seipd);

            var e = Assert.Throws<PgpException>(() =>
                PgpMLKemX25519Test.FindEncryptedData(message, recipient.PrivateKey.KeyId)
                    .GetDataStream(recipient.PrivateKey));
            Assert.That(e.Message, Is.EqualTo("exception decrypting session key"));
        }

        [Test]
        public void AlgorithmMismatchIsReportedAsGenericFailure()
        {
            Recipient[] rfc = RfcRecipients();
            Recipient x25519 = rfc[0];
            Recipient mlkem = rfc[1];
            Recipient ecdh = GeneratedRecipients().First(r => r.PublicKey.Algorithm == PublicKeyAlgorithmTag.ECDH);

            byte[] x25519Message = EncryptV2(new[]{ x25519.PublicKey }, Content);
            byte[] mlkemMessage = EncryptV2(new[]{ mlkem.PublicKey }, Content);

            void Check(byte[] message, long keyId, PgpPrivateKey privateKey)
            {
                var e = Assert.Throws<PgpException>(() =>
                    PgpMLKemX25519Test.FindEncryptedData(message, keyId).GetDataStream(privateKey));
                Assert.That(e.Message, Is.EqualTo("exception decrypting session key"));
            }

            // a PKESK for 35 offered to an X25519 key, an ECDH key, and the other way around
            Check(mlkemMessage, mlkem.PrivateKey.KeyId, x25519.PrivateKey);
            Check(mlkemMessage, mlkem.PrivateKey.KeyId, ecdh.PrivateKey);
            Check(x25519Message, x25519.PrivateKey.KeyId, mlkem.PrivateKey);
            Check(x25519Message, x25519.PrivateKey.KeyId, ecdh.PrivateKey);
        }

        /// <summary>RFC 9580 9.2: no encryption to a version 6 ECDH key that announces other KDF parameters.</summary>
        [Test]
        public void EcdhKeyWithOtherKdfParametersIsRefused()
        {
            AsymmetricCipherKeyPair pair = PgpV6KeyGenerationTest.GenerateEc(SecObjectIdentifiers.SecP384r1);
            var ecKey = (ECPublicKeyParameters)pair.Public;

            // SHA-256 with AES-128 is the form for P-256, not for P-384
            var bcpgKey = new ECDHPublicBcpgKey(ecKey.PublicKeyParamSet, ecKey.Q, HashAlgorithmTag.Sha256,
                SymmetricKeyAlgorithmTag.Aes128);
            var v6 = new PgpPublicKey(new PublicKeyPacket(PublicKeyPacket.Version6, PublicKeyAlgorithmTag.ECDH,
                DateTime.UtcNow, bcpgKey));
            var v4 = new PgpPublicKey(new PublicKeyPacket(PublicKeyPacket.Version4, PublicKeyAlgorithmTag.ECDH,
                DateTime.UtcNow, bcpgKey));

            var generator = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, AeadAlgorithmTag.Ocb, Random);
            Assert.Throws<PgpException>(() => generator.AddMethod(v6));
            Assert.DoesNotThrow(() => generator.AddMethod(v4));
        }

        /// <summary>An anonymous recipient: all the keys can be tried.</summary>
        [Test]
        public void AnonymousRecipientDecrypts()
        {
            Recipient recipient = RfcRecipients()[0];
            byte[] message = EncryptV2(new[]{ recipient.PublicKey }, Content);

            byte[][] packets = PgpUnsupportedVersionTest.SplitPackets(message);
            var pkesk = PgpV6TestUtilities.ReadPacket<PublicKeyEncSessionPacket>(packets[0]);
            var anonymous = PublicKeyEncSessionPacket.CreateV6Packet(0, null, pkesk.Algorithm,
                pkesk.GetEncSessionKey());
            byte[] anonymousMessage = Arrays.Concatenate(anonymous.GetEncoded(PacketFormat.Current),
                Arrays.ConcatenateAll(packets.Skip(1).ToArray()));

            var list = (PgpEncryptedDataList)new PgpObjectFactory(anonymousMessage).NextPgpObject();
            var encData = (PgpPublicKeyEncryptedData)list[0];
            Assert.That(encData.KeyId, Is.EqualTo(0L));
            Assert.That(encData.KeyVersion, Is.EqualTo(0));
            Assert.That(encData.GetKeyFingerprint(), Is.Null);

            PgpMLKemX25519Test.Decrypted result = PgpMLKemX25519Test.ReadContent(encData,
                encData.GetDataStream(recipient.PrivateKey), null, encData.GetSymmetricAlgorithm(recipient.PrivateKey));
            Assert.That(result.Content, Is.EqualTo(Content));
        }

        // RFC 9580 A.8, X25519 with OCB.
        [Test]
        public void Rfc9580X25519Message()
        {
            Recipient recipient = RfcRecipients()[0];
            byte[] message = PgpV6TestUtilities.LoadRfc9580("a8-x25519-ocb-message.asc");

            var list = (PgpEncryptedDataList)new PgpObjectFactory(message).NextPgpObject();
            var encData = (PgpPublicKeyEncryptedData)list[0];
            Assert.That(encData.Version, Is.EqualTo(6));
            Assert.That(encData.KeyVersion, Is.EqualTo(6));
            Assert.That(Hex.ToHexString(encData.GetKeyFingerprint()),
                Is.EqualTo("12c83f1e706f6308fe151a417743a1f033790e93e9978488d1db378da9930885"));
            Assert.That(encData.KeyId, Is.EqualTo(recipient.PublicKey.KeyId));
            Assert.That(encData.GetSymmetricAlgorithm(recipient.PrivateKey), Is.EqualTo(SymmetricKeyAlgorithmTag.Aes128));

            using (Stream stream = encData.GetDataStream(recipient.PrivateKey))
            {
                var factory = new PgpObjectFactory(stream);
                var literal = (PgpLiteralData)factory.NextPgpObject();
                Assert.That(Strings.FromUtf8ByteArray(Streams.ReadAll(literal.GetDataStream())),
                    Is.EqualTo("Hello, world!"));
                Assert.That(factory.NextPgpObject(), Is.InstanceOf<PgpPadding>());
                Assert.That(encData.Verify(), Is.True);
            }
        }

        // RFC 9980 A.1.3 and A.2.4.
        [Test]
        public void Rfc9980Messages()
        {
            Recipient[] rfc = RfcRecipients();

            // A.1.3: to a version 6 ML-KEM-768+X25519 key, signed by the version 6 Ed25519 key
            var a1 = new PgpPublicKeyRing(PgpV6TestUtilities.LoadRfc9980("a1-public-key.asc"));
            byte[] a13 = PgpV6TestUtilities.LoadRfc9980("a1-message.asc");
            PgpMLKemX25519Test.Decrypted result = PgpMLKemX25519Test.Decrypt(a13, rfc[1].PrivateKey, a1.GetPublicKey());
            Assert.That(Strings.FromUtf8ByteArray(result.Content), Is.EqualTo("Testing\n"));
            Assert.That(result.Algorithm, Is.EqualTo(SymmetricKeyAlgorithmTag.Aes256));
            Assert.That(result.OnePassSignatureCount, Is.EqualTo(1));
            Assert.That(result.SignatureVerified, Is.True);
            Assert.That(result.IntegrityVerified, Is.True);

            // A.2.4: a version 6 PKESK to a version 4 ML-KEM-768+X25519 subkey
            byte[] a24 = PgpMLKemX25519Test.LoadA2("a2-seipdv2-message.asc");
            result = PgpMLKemX25519Test.Decrypt(a24, rfc[2].PrivateKey, PgpMLKemX25519Test.A2PublicRing().GetPublicKey());
            Assert.That(Strings.FromUtf8ByteArray(result.Content), Is.EqualTo("Testing\n"));
            Assert.That(result.SignatureVerified, Is.True);
            Assert.That(result.IntegrityVerified, Is.True);
        }
    }
}
