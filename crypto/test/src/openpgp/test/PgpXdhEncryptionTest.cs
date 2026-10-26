using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    /// <summary>Tests for the X25519 and X448 encryption algorithms of RFC 9580 (5.1.6, 5.1.7).</summary>
    [TestFixture]
    public class PgpXdhEncryptionTest
    {
        private static readonly SecureRandom Random = new SecureRandom();

        private static readonly byte[] Content = Strings.ToUtf8ByteArray("encrypted to a native Diffie-Hellman key");

        /// <summary>An Ed25519 key with an encryption subkey of the given algorithm (X25519 or X448).</summary>
        internal static PgpSecretKeyRing GenerateRing(PublicKeyAlgorithmTag subkeyAlgorithm, char[] passPhrase,
            out PgpPublicKeyRing publicRing)
        {
            var primary = new PgpKeyPair(PublicKeyAlgorithmTag.Ed25519,
                PgpEdDsaV4SignatureTest.GenerateKeyPair(PublicKeyAlgorithmTag.Ed25519), DateTime.UtcNow);

            var hashed = new PgpSignatureSubpacketGenerator();
            hashed.SetKeyFlags(false, PgpKeyFlags.CanCertify | PgpKeyFlags.CanSign);
            hashed.SetIssuerFingerprint(false, primary.PublicKey);

            var encAlgorithm = passPhrase == null ? SymmetricKeyAlgorithmTag.Null : SymmetricKeyAlgorithmTag.Aes256;
            var generator = new PgpKeyRingGenerator(PgpSignature.PositiveCertification, primary, "xdh@example.org",
                encAlgorithm, HashAlgorithmTag.Sha512, passPhrase ?? new char[0], true, hashed.Generate(), null,
                Random);

            generator.AddSubKey(NewSubkeyPair(subkeyAlgorithm), SubkeyPackets(primary), null, HashAlgorithmTag.Sha512);

            publicRing = generator.GeneratePublicKeyRing();
            return generator.GenerateSecretKeyRing();
        }

        internal static PgpKeyPair NewSubkeyPair(PublicKeyAlgorithmTag algorithm)
        {
            if (algorithm == PublicKeyAlgorithmTag.X25519)
            {
                var privateKey = new X25519PrivateKeyParameters(Random);
                return new PgpKeyPair(algorithm, privateKey.GeneratePublicKey(), privateKey, DateTime.UtcNow);
            }
            else
            {
                var privateKey = new X448PrivateKeyParameters(Random);
                return new PgpKeyPair(algorithm, privateKey.GeneratePublicKey(), privateKey, DateTime.UtcNow);
            }
        }

        private static PgpSignatureSubpacketVector SubkeyPackets(PgpKeyPair primary)
        {
            var hashed = new PgpSignatureSubpacketGenerator();
            hashed.SetKeyFlags(false, PgpKeyFlags.CanEncryptCommunications | PgpKeyFlags.CanEncryptStorage);
            hashed.SetIssuerFingerprint(false, primary.PublicKey);
            return hashed.Generate();
        }

        private static PgpPublicKey Subkey(PgpPublicKeyRing ring) =>
            ring.GetPublicKeys().First(k => !k.IsMasterKey);

        private static PgpPrivateKey SubkeyPrivate(PgpSecretKeyRing ring, char[] passPhrase) =>
            ring.GetSecretKeys().First(k => !k.IsMasterKey).ExtractPrivateKey(passPhrase ?? new char[0]);

        private static readonly object[][] Algorithms =
        {
            new object[]{ PublicKeyAlgorithmTag.X25519, 32 },
            new object[]{ PublicKeyAlgorithmTag.X448, 56 },
        };

        [TestCaseSource(nameof(Algorithms))]
        public void RoundTrip(PublicKeyAlgorithmTag algorithm, int ephemeralLength)
        {
            PgpSecretKeyRing secretRing = GenerateRing(algorithm, null, out PgpPublicKeyRing publicRing);
            PgpPrivateKey privateKey = SubkeyPrivate(secretRing, null);
            PgpPublicKey subkey = Subkey(publicRing);

            Assert.That(subkey.Algorithm, Is.EqualTo(algorithm));
            Assert.That(subkey.IsEncryptionKey, Is.True);
            Assert.That(privateKey.Key, Is.InstanceOf(algorithm == PublicKeyAlgorithmTag.X25519
                ? typeof(X25519PrivateKeyParameters) : typeof(X448PrivateKeyParameters)));

            foreach (var cipher in new[]
            {
                SymmetricKeyAlgorithmTag.Aes128, SymmetricKeyAlgorithmTag.Aes192, SymmetricKeyAlgorithmTag.Aes256,
            })
            {
                byte[] message = PgpMLKemX25519Test.Encrypt(new[]{ subkey }, Content, cipher);

                // ephemeral key, length octet, algorithm octet, wrapped session key (8 octets longer than the key)
                var pkesk = PgpV6TestUtilities.ReadPacket<PublicKeyEncSessionPacket>(
                    PgpUnsupportedVersionTest.SplitPackets(message)[0]);
                Assert.That(pkesk.Version, Is.EqualTo(3));
                Assert.That(pkesk.Algorithm, Is.EqualTo(algorithm));
                byte[] fields = pkesk.GetEncSessionKey()[0];
                int keyLength = PgpUtilities.GetKeySize(cipher) / 8;
                Assert.That(fields.Length, Is.EqualTo(ephemeralLength + 1 + 1 + keyLength + 8));
                Assert.That(fields[ephemeralLength], Is.EqualTo(1 + keyLength + 8));
                Assert.That(fields[ephemeralLength + 1], Is.EqualTo((byte)cipher));

                PgpMLKemX25519Test.Decrypted result = PgpMLKemX25519Test.Decrypt(message, privateKey);
                Assert.That(result.Content, Is.EqualTo(Content));
                Assert.That(result.IntegrityVerified, Is.True);
                Assert.That(result.Algorithm, Is.EqualTo(cipher));
            }
        }

        [TestCaseSource(nameof(Algorithms))]
        public void OnlyAesIsAllowedWithIntegrityProtection(PublicKeyAlgorithmTag algorithm, int ephemeralLength)
        {
            GenerateRing(algorithm, null, out PgpPublicKeyRing publicRing);
            PgpPublicKey subkey = Subkey(publicRing);

            Assert.Throws<PgpException>(() =>
                new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Camellia256, true, Random).AddMethod(subkey));
            Assert.Throws<PgpException>(() =>
                new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.TripleDes, true, Random).AddMethod(subkey));

            // never with the SED packet
            Assert.Throws<PgpException>(() =>
                new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, false, Random).AddMethod(subkey));
        }

        private static byte[] MutatePkeskFields(byte[] message, int position)
        {
            byte[][] packets = PgpUnsupportedVersionTest.SplitPackets(message);
            byte[] pkesk = Arrays.Clone(packets[0]);
            int header = PgpMLKemX25519Test.HeaderLength(pkesk);

            // version 3 PKESK: version, key ID, algorithm, then the algorithm-specific fields
            pkesk[header + 1 + 8 + 1 + position] ^= 0x01;
            return Arrays.Concatenate(pkesk, Arrays.ConcatenateAll(packets.Skip(1).ToArray()));
        }

        [TestCaseSource(nameof(Algorithms))]
        public void TamperedSessionKeyPacketsAreRejectedUniformly(PublicKeyAlgorithmTag algorithm, int ephemeralLength)
        {
            PgpSecretKeyRing secretRing = GenerateRing(algorithm, null, out PgpPublicKeyRing publicRing);
            PgpPrivateKey privateKey = SubkeyPrivate(secretRing, null);
            byte[] message = PgpMLKemX25519Test.Encrypt(new[]{ Subkey(publicRing) }, Content,
                SymmetricKeyAlgorithmTag.Aes256);
            int fieldsLength = ephemeralLength + 1 + 1 + 32 + 8;

            var messages = new HashSet<string>();
            for (int i = 0; i < fieldsLength; ++i)
            {
                byte[] modified = MutatePkeskFields(message, i);

                var e = Assert.Throws<PgpException>(() =>
                    PgpMLKemX25519Test.FindEncryptedData(modified, privateKey.KeyId).GetDataStream(privateKey),
                    "position " + i);
                messages.Add(e.Message);
            }
            Assert.That(messages.Count, Is.EqualTo(1), string.Join("; ", messages));

            // a different key of the same type cannot decrypt either
            PgpSecretKeyRing other = GenerateRing(algorithm, null, out _);
            PgpPrivateKey otherKey = SubkeyPrivate(other, null);
            var wrongKey = Assert.Throws<PgpException>(() =>
                PgpMLKemX25519Test.FindEncryptedData(message, privateKey.KeyId).GetDataStream(otherKey));
            Assert.That(wrongKey.Message, Is.EqualTo(messages.Single()));
        }

        [TestCaseSource(nameof(Algorithms))]
        public void LowOrderEphemeralKeyIsRejected(PublicKeyAlgorithmTag algorithm, int ephemeralLength)
        {
            PgpSecretKeyRing secretRing = GenerateRing(algorithm, null, out PgpPublicKeyRing publicRing);
            PgpPrivateKey privateKey = SubkeyPrivate(secretRing, null);
            byte[] message = PgpMLKemX25519Test.Encrypt(new[]{ Subkey(publicRing) }, Content,
                SymmetricKeyAlgorithmTag.Aes256);

            byte[][] packets = PgpUnsupportedVersionTest.SplitPackets(message);
            byte[] pkesk = Arrays.Clone(packets[0]);
            int fieldsStart = PgpMLKemX25519Test.HeaderLength(pkesk) + 1 + 8 + 1;
            Arrays.Fill(pkesk, fieldsStart, fieldsStart + ephemeralLength, 0);
            byte[] modified = Arrays.Concatenate(pkesk, Arrays.ConcatenateAll(packets.Skip(1).ToArray()));

            var e = Assert.Throws<PgpException>(() =>
                PgpMLKemX25519Test.FindEncryptedData(modified, privateKey.KeyId).GetDataStream(privateKey));
            Assert.That(e.Message, Does.Contain("exception decrypting session key"));
        }

        [Test]
        public void LegacyCurve25519KeysStillWork()
        {
            var generator = new X25519KeyPairGenerator();
            generator.Init(new X25519KeyGenerationParameters(Random));
            var keyPair = new PgpKeyPair(PublicKeyAlgorithmTag.ECDH, generator.GenerateKeyPair(), DateTime.UtcNow);

            Assert.That(keyPair.PublicKey.PublicKeyPacket.Key, Is.InstanceOf<ECDHPublicBcpgKey>());

            byte[] message = PgpMLKemX25519Test.Encrypt(new[]{ keyPair.PublicKey }, Content);
            PgpMLKemX25519Test.Decrypted result = PgpMLKemX25519Test.Decrypt(message, keyPair.PrivateKey);
            Assert.That(result.Content, Is.EqualTo(Content));
        }

        [TestCaseSource(nameof(Algorithms))]
        public void ProtectedKeysRoundTrip(PublicKeyAlgorithmTag algorithm, int ephemeralLength)
        {
            char[] passPhrase = "pass phrase".ToCharArray();
            PgpSecretKeyRing created = GenerateRing(algorithm, passPhrase, out PgpPublicKeyRing publicRing);
            var secretRing = new PgpSecretKeyRing(created.GetEncoded());

            PgpPrivateKey privateKey = SubkeyPrivate(secretRing, passPhrase);
            byte[] message = PgpMLKemX25519Test.Encrypt(new[]{ Subkey(publicRing) }, Content);

            Assert.That(PgpMLKemX25519Test.Decrypt(message, privateKey).Content, Is.EqualTo(Content));
            Assert.Throws<PgpException>(() => SubkeyPrivate(secretRing, "wrong".ToCharArray()));
        }

        /// <summary>The ephemeral key and wrapped key follow RFC 9580, checked with a known ephemeral key.</summary>
        [Test]
        public void EncryptionWithKnownEphemeralKey()
        {
            var recipientPrivate = new X25519PrivateKeyParameters(Random);
            var ephemeralPrivate = new X25519PrivateKeyParameters(Random);
            var ephemeral = new Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair(ephemeralPrivate.GeneratePublicKey(),
                ephemeralPrivate);

            byte[] sessionKey = new byte[32];
            Random.NextBytes(sessionKey);

            byte[] fields = PgpXdhKem.X25519.Encrypt(recipientPrivate.GeneratePublicKey(), ephemeral, sessionKey,
                isVersion3Pkesk: true, SymmetricKeyAlgorithmTag.Aes256, Random);

            Assert.That(Arrays.AreEqual(ephemeralPrivate.GeneratePublicKey().GetEncoded(),
                Arrays.CopyOfRange(fields, 0, 32)), Is.True);

            byte[] recovered = PgpXdhKem.X25519.Decrypt(recipientPrivate,
                recipientPrivate.GeneratePublicKey().GetEncoded(), fields, isVersion3Pkesk: true,
                out SymmetricKeyAlgorithmTag algorithm);
            Assert.That(algorithm, Is.EqualTo(SymmetricKeyAlgorithmTag.Aes256));
            Assert.That(recovered, Is.EqualTo(sessionKey));

            // the version 6 form has no algorithm octet and decrypts the same way
            byte[] v6Fields = PgpXdhKem.X25519.Encrypt(recipientPrivate.GeneratePublicKey(), ephemeral, sessionKey,
                isVersion3Pkesk: false, SymmetricKeyAlgorithmTag.Aes256, Random);
            Assert.That(v6Fields.Length, Is.EqualTo(fields.Length - 1));
            Assert.That(PgpXdhKem.X25519.Decrypt(recipientPrivate, recipientPrivate.GeneratePublicKey().GetEncoded(),
                v6Fields, isVersion3Pkesk: false, out _), Is.EqualTo(sessionKey));
        }
    }
}
