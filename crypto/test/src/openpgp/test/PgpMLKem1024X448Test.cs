using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    /// <summary>Tests for the ML-KEM-1024+X448 composite KEM, algorithm 36 of RFC 9980.</summary>
    [TestFixture]
    public class PgpMLKem1024X448Test
    {
        private static readonly SecureRandom Random = new SecureRandom();

        private static readonly byte[] Content = Strings.ToUtf8ByteArray("a message for ML-KEM-1024+X448");

        private static PgpKeyPair NewKeyPair(int version = 6)
        {
            var privateKey = new MLKem1024X448PrivateKeyParameters(Random);
            return new PgpKeyPair(version, PublicKeyAlgorithmTag.MLKem1024_X448, privateKey.GeneratePublicKey(),
                privateKey, DateTime.UtcNow);
        }

        /// <summary>A version 6 ring with an Ed25519 primary key and an ML-KEM-1024+X448 subkey.</summary>
        private static PgpSecretKeyRing GenerateRing(out PgpPublicKeyRing publicRing)
        {
            var edGen = new Ed25519KeyPairGenerator();
            edGen.Init(new Ed25519KeyGenerationParameters(Random));
            var primary = new PgpKeyPair(6, PublicKeyAlgorithmTag.Ed25519, edGen.GenerateKeyPair(), DateTime.UtcNow);

            var hashed = new PgpSignatureSubpacketGenerator();
            hashed.SetKeyFlags(false, PgpKeyFlags.CanCertify | PgpKeyFlags.CanSign);
            var krg = new PgpKeyRingGenerator(PgpSignature.PositiveCertification, primary, "pq@example.org",
                SymmetricKeyAlgorithmTag.Null, HashAlgorithmTag.Sha512, new char[0], true, hashed.Generate(), null,
                Random);

            var subHashed = new PgpSignatureSubpacketGenerator();
            subHashed.SetKeyFlags(false, PgpKeyFlags.CanEncryptCommunications | PgpKeyFlags.CanEncryptStorage);
            krg.AddSubKey(NewKeyPair(), subHashed.Generate(), null, HashAlgorithmTag.Sha512);

            publicRing = krg.GeneratePublicKeyRing();
            return krg.GenerateSecretKeyRing();
        }

        private static PgpPublicKey Subkey(PgpPublicKeyRing ring) =>
            ring.GetPublicKeys().First(k => k.Algorithm == PublicKeyAlgorithmTag.MLKem1024_X448);

        private static PgpSecretKey Subkey(PgpSecretKeyRing ring) =>
            ring.GetSecretKeys().First(k => k.PublicKey.Algorithm == PublicKeyAlgorithmTag.MLKem1024_X448);

        private static int IndexOf(byte[] data, byte[] pattern)
        {
            for (int i = 0; i + pattern.Length <= data.Length; ++i)
            {
                if (Arrays.AreEqual(Arrays.CopyOfRange(data, i, i + pattern.Length), pattern))
                    return i;
            }
            return -1;
        }

        [Test]
        public void KeyRoundTrip()
        {
            PgpSecretKeyRing secretRing = GenerateRing(out PgpPublicKeyRing publicRing);

            PgpPublicKey subkey = Subkey(new PgpPublicKeyRing(publicRing.GetEncoded()));
            Assert.That(subkey.Version, Is.EqualTo(6));
            Assert.That(subkey.IsEncryptionKey, Is.True);
            Assert.That(subkey.GetFingerprint().Length, Is.EqualTo(32));

            var publicParams = (MLKem1024X448PublicKeyParameters)subkey.GetKey();
            PgpPrivateKey privateKey = Subkey(new PgpSecretKeyRing(secretRing.GetEncoded()))
                .ExtractPrivateKey(new char[0]);
            var privateParams = (MLKem1024X448PrivateKeyParameters)privateKey.Key;
            MLKem1024X448PublicKeyParameters derived = privateParams.GeneratePublicKey();

            Assert.That(Arrays.AreEqual(publicParams.X448Key.GetEncoded(), derived.X448Key.GetEncoded()), Is.True);
            Assert.That(Arrays.AreEqual(publicParams.MLKemKey.GetEncoded(), derived.MLKemKey.GetEncoded()), Is.True);
            Assert.That(derived.X448Key.GetEncoded().Length, Is.EqualTo(56));
            Assert.That(derived.MLKemKey.GetEncoded().Length, Is.EqualTo(1568));
        }

        [Test]
        public void OnlyVersion6KeysAndMatchingTypes()
        {
            var privateKey = new MLKem1024X448PrivateKeyParameters(Random);
            MLKem1024X448PublicKeyParameters publicKey = privateKey.GeneratePublicKey();

            Assert.Throws<ArgumentException>(() =>
                new PgpPublicKey(4, PublicKeyAlgorithmTag.MLKem1024_X448, publicKey, DateTime.UtcNow));
            Assert.Throws<ArgumentException>(() => NewKeyPair(4));
            Assert.Throws<ArgumentException>(() =>
                new PgpPublicKey(6, PublicKeyAlgorithmTag.MLKem768_X25519, publicKey, DateTime.UtcNow));
            Assert.Throws<ArgumentException>(() =>
                new PgpPublicKey(6, PublicKeyAlgorithmTag.MLKem1024_X448,
                    new MLKem768X25519PrivateKeyParameters(Random).GeneratePublicKey(), DateTime.UtcNow));
            Assert.Throws<ArgumentException>(() =>
                new PgpPublicKey(6, PublicKeyAlgorithmTag.X448, publicKey, DateTime.UtcNow));
        }

        [Test]
        public void CorruptedSecretRejected()
        {
            PgpSecretKeyRing secretRing = GenerateRing(out PgpPublicKeyRing _);
            byte[] encoded = secretRing.GetEncoded();
            PgpSecretKey subkey = Subkey(secretRing);
            byte[] material = ((MLKem1024X448PublicBcpgKey)subkey.PublicKey.PublicKeyPacket.Key).GetKey();

            int pos = IndexOf(encoded, material);
            Assert.That(pos, Is.GreaterThan(0));

            // unprotected v6 secret key: public material | usage (1) | X448 secret (56) | ML-KEM seed (64)
            byte[] modified = Arrays.Clone(encoded);
            modified[pos + material.Length + 1 + 56 + 5] ^= 0x01;
            Assert.Throws<PgpException>(() => Subkey(new PgpSecretKeyRing(modified)).ExtractPrivateKey(new char[0]));

            modified = Arrays.Clone(encoded);
            modified[pos + material.Length + 1 + 5] ^= 0x01;
            Assert.Throws<PgpException>(() => Subkey(new PgpSecretKeyRing(modified)).ExtractPrivateKey(new char[0]));
        }

        [Test]
        public void EncryptAndDecryptBothVersions()
        {
            PgpSecretKeyRing secretRing = GenerateRing(out PgpPublicKeyRing publicRing);
            PgpPrivateKey privateKey = Subkey(secretRing).ExtractPrivateKey(new char[0]);
            PgpPublicKey subkey = Subkey(publicRing);

            foreach (var algorithm in new[]
            {
                SymmetricKeyAlgorithmTag.Aes128, SymmetricKeyAlgorithmTag.Aes192, SymmetricKeyAlgorithmTag.Aes256,
            })
            {
                byte[] v1 = PgpMLKemX25519Test.Encrypt(new[]{ subkey }, Content, algorithm);
                var data = PgpMLKemX25519Test.FindEncryptedData(v1, privateKey.KeyId);
                Assert.That(data.Version, Is.EqualTo(3));
                Assert.That(data.IsAead, Is.False);

                PgpMLKemX25519Test.Decrypted result = PgpMLKemX25519Test.Decrypt(v1, privateKey);
                Assert.That(result.Content, Is.EqualTo(Content));
                Assert.That(result.IntegrityVerified, Is.True);
                Assert.That(result.Algorithm, Is.EqualTo(algorithm));
            }

            foreach (var aead in new[]{ AeadAlgorithmTag.Eax, AeadAlgorithmTag.Ocb, AeadAlgorithmTag.Gcm })
            {
                byte[] v2 = PgpV6PkeskTest.EncryptV2(new[]{ subkey }, Content, SymmetricKeyAlgorithmTag.Aes256, aead);
                var data = PgpMLKemX25519Test.FindEncryptedData(v2, privateKey.KeyId);
                Assert.That(data.Version, Is.EqualTo(6));
                Assert.That(data.IsAead, Is.True);

                PgpMLKemX25519Test.Decrypted result = PgpMLKemX25519Test.Decrypt(v2, privateKey);
                Assert.That(result.Content, Is.EqualTo(Content));
                Assert.That(result.IntegrityVerified, Is.True);
            }
        }

        // The PKESK fields have the layout of RFC 9980 4.2.3.
        [Test]
        public void PkeskLayout()
        {
            GenerateRing(out PgpPublicKeyRing publicRing);
            PgpPublicKey subkey = Subkey(publicRing);

            byte[] v3 = PgpMLKemX25519Test.Encrypt(new[]{ subkey }, Content);
            var pkesk3 = (PublicKeyEncSessionPacket)BcpgInputStream.Wrap(new MemoryStream(v3, false)).ReadPacket();
            byte[] fields3 = pkesk3.GetEncSessionKey()[0];
            // 56 + 1568 + length + algorithm + wrapped (32-byte key + 8)
            Assert.That(fields3.Length, Is.EqualTo(56 + 1568 + 1 + 1 + 40));
            Assert.That(fields3[56 + 1568], Is.EqualTo(1 + 40));
            Assert.That(fields3[56 + 1568 + 1], Is.EqualTo((byte)SymmetricKeyAlgorithmTag.Aes256));

            byte[] v6 = PgpV6PkeskTest.EncryptV2(new[]{ subkey }, Content);
            var pkesk6 = (PublicKeyEncSessionPacket)BcpgInputStream.Wrap(new MemoryStream(v6, false)).ReadPacket();
            byte[] fields6 = pkesk6.GetEncSessionKey()[0];
            Assert.That(fields6.Length, Is.EqualTo(56 + 1568 + 1 + 40));
            Assert.That(fields6[56 + 1568], Is.EqualTo(40));
        }

        [Test]
        public void TamperedPkeskGivesGenericError()
        {
            PgpSecretKeyRing secretRing = GenerateRing(out PgpPublicKeyRing publicRing);
            PgpPrivateKey privateKey = Subkey(secretRing).ExtractPrivateKey(new char[0]);
            byte[] message = PgpMLKemX25519Test.Encrypt(new[]{ Subkey(publicRing) }, Content);

            var pkesk = (PublicKeyEncSessionPacket)BcpgInputStream.Wrap(new MemoryStream(message, false)).ReadPacket();
            byte[] fields = pkesk.GetEncSessionKey()[0];
            int pos = IndexOf(message, Arrays.CopyOfRange(fields, 0, 64));
            Assert.That(pos, Is.GreaterThan(0));

            // flip a bit in the X448 share, the ML-KEM ciphertext, and the wrapped key
            foreach (int offset in new[]{ 3, 56 + 100, fields.Length - 3 })
            {
                byte[] modified = Arrays.Clone(message);
                modified[pos + offset] ^= 0x10;

                var ex = Assert.Throws<PgpException>(() =>
                    PgpMLKemX25519Test.FindEncryptedData(modified, privateKey.KeyId).GetDataStream(privateKey));
                Assert.That(ex.Message, Is.EqualTo("exception decrypting session key"), "offset " + offset);
            }
        }

        /// <summary>
        /// An X448 ciphertext of low order gives an all-zero shared secret (RFC 9980 3.4, RFC 7748 6.2), which the
        /// KEM refuses; through the public API it is the generic error.
        /// </summary>
        [Test]
        public void LowOrderX448CipherTextIsRejected()
        {
            PgpSecretKeyRing secretRing = GenerateRing(out PgpPublicKeyRing publicRing);
            PgpPrivateKey privateKey = Subkey(secretRing).ExtractPrivateKey(new char[0]);
            byte[] message = PgpMLKemX25519Test.Encrypt(new[]{ Subkey(publicRing) }, Content);

            var pkesk = (PublicKeyEncSessionPacket)BcpgInputStream.Wrap(new MemoryStream(message, false)).ReadPacket();
            byte[] fields = pkesk.GetEncSessionKey()[0];
            int pos = IndexOf(message, Arrays.CopyOfRange(fields, 0, 64));
            Assert.That(pos, Is.GreaterThan(0));

            // u = 0, u = 1 and u = p - 1, little-endian
            byte[] one = new byte[56];
            one[0] = 1;
            byte[] pMinusOne = new byte[56];
            Arrays.Fill(pMinusOne, 0xFF);
            pMinusOne[0] = 0xFE;
            pMinusOne[28] = 0xFE;

            var privateParams = (MLKem1024X448PrivateKeyParameters)privateKey.Key;
            byte[] recipient = privateParams.GeneratePublicKey().X448Key.GetEncoded();
            foreach (byte[] point in new[]{ new byte[56], one, pMinusOne })
            {
                Assert.Throws<InvalidOperationException>(() => PgpCompositeKem.MLKem1024X448.Decapsulate(
                    privateParams.X448Key, privateParams.MLKemKey, recipient, point, new byte[1568]),
                    Hex.ToHexString(point));

                byte[] modified = Arrays.Clone(message);
                Array.Copy(point, 0, modified, pos, point.Length);
                var ex = Assert.Throws<PgpException>(() =>
                    PgpMLKemX25519Test.FindEncryptedData(modified, privateKey.KeyId).GetDataStream(privateKey));
                Assert.That(ex.Message, Is.EqualTo("exception decrypting session key"), Hex.ToHexString(point));
            }
        }

        /// <summary>
        /// A certificate whose ECDH component is a point of low order cannot be encrypted to: the zero point must not
        /// appear in the data structures (RFC 9980 3.4), and it would give a predictable ECDH key share.
        /// </summary>
        [Test]
        public void LowOrderEcdhRecipientKeyIsRefused()
        {
            var mlKem768 = new MLKem768X25519PrivateKeyParameters(Random).GeneratePublicKey().MLKemKey;
            var mlKem1024 = new MLKem1024X448PrivateKeyParameters(Random).GeneratePublicKey().MLKemKey;

            byte[] x25519One = new byte[32];
            x25519One[0] = 1;
            byte[] x448One = new byte[56];
            x448One[0] = 1;
            var recipients = new[]
            {
                new PgpPublicKey(4, PublicKeyAlgorithmTag.MLKem768_X25519, new MLKem768X25519PublicKeyParameters(
                    new X25519PublicKeyParameters(new byte[32]), mlKem768), DateTime.UtcNow),
                new PgpPublicKey(6, PublicKeyAlgorithmTag.MLKem768_X25519, new MLKem768X25519PublicKeyParameters(
                    new X25519PublicKeyParameters(x25519One), mlKem768), DateTime.UtcNow),
                new PgpPublicKey(6, PublicKeyAlgorithmTag.MLKem1024_X448, new MLKem1024X448PublicKeyParameters(
                    new X448PublicKeyParameters(new byte[56]), mlKem1024), DateTime.UtcNow),
                new PgpPublicKey(6, PublicKeyAlgorithmTag.MLKem1024_X448, new MLKem1024X448PublicKeyParameters(
                    new X448PublicKeyParameters(x448One), mlKem1024), DateTime.UtcNow),
            };
            foreach (PgpPublicKey recipient in recipients)
            {
                var generator = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, true, Random);
                if (recipient.Version == 6)
                {
                    generator = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, AeadAlgorithmTag.Ocb,
                        Random);
                }
                generator.AddMethod(recipient);

                var output = new MemoryStream();
                Exception e = Assert.Throws<PgpException>(() => generator.Open(output, new byte[1 << 10]).Dispose(),
                    recipient.Algorithm + " v" + recipient.Version);
                while (e.InnerException != null && !e.Message.EndsWith("key agreement failed"))
                {
                    e = e.InnerException;
                }
                Assert.That(e.Message, Does.EndWith("key agreement failed"), recipient.Algorithm.ToString());
            }
        }

        [Test]
        public void WrongKeyTypeCannotDecrypt()
        {
            PgpSecretKeyRing secretRing = GenerateRing(out PgpPublicKeyRing publicRing);
            PgpPrivateKey privateKey = Subkey(secretRing).ExtractPrivateKey(new char[0]);

            PgpMLKemX25519Test.GenerateRing("a", null, out PgpPublicKeyRing otherPublic);
            byte[] message = PgpMLKemX25519Test.Encrypt(new[]{ PgpMLKemX25519Test.MLKemSubkey(otherPublic) }, Content);

            var data = PgpMLKemX25519Test.FindEncryptedData(message, PgpMLKemX25519Test.MLKemSubkey(otherPublic).KeyId);
            Assert.Throws<PgpException>(() => data.GetDataStream(privateKey));
        }

        [Test]
        public void EncryptionRules()
        {
            GenerateRing(out PgpPublicKeyRing publicRing);
            PgpPublicKey subkey = Subkey(publicRing);

            var noIntegrity = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, false, Random);
            Assert.Throws<PgpException>(() => noIntegrity.AddMethod(subkey));

            var camellia = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Camellia256, true, Random);
            Assert.Throws<PgpException>(() => camellia.AddMethod(subkey));

            // with SEIPD v2 the cipher is not constrained by the KEM: the session key is wrapped as is
            byte[] v2 = PgpV6PkeskTest.EncryptV2(new[]{ subkey }, Content, SymmetricKeyAlgorithmTag.Camellia256,
                AeadAlgorithmTag.Ocb);
            Assert.That(v2.Length, Is.GreaterThan(0));
        }

        [Test]
        public void MixedCompositeRecipients()
        {
            PgpSecretKeyRing secret1024 = GenerateRing(out PgpPublicKeyRing public1024);
            PgpSecretKeyRing secret768 = PgpMLKemX25519Test.GenerateRing("b", null, out PgpPublicKeyRing public768);

            byte[] message = PgpMLKemX25519Test.Encrypt(
                new[]{ Subkey(public1024), PgpMLKemX25519Test.MLKemSubkey(public768) }, Content);

            PgpMLKemX25519Test.Decrypted result = PgpMLKemX25519Test.Decrypt(message,
                Subkey(secret1024).ExtractPrivateKey(new char[0]));
            Assert.That(result.Content, Is.EqualTo(Content));
            result = PgpMLKemX25519Test.Decrypt(message,
                PgpMLKemX25519Test.MLKemSubkey(secret768).ExtractPrivateKey(new char[0]));
            Assert.That(result.Content, Is.EqualTo(Content));
        }

        [Test]
        public void ProtectedSecretKey()
        {
            PgpSecretKeyRing secretRing = GenerateRing(out PgpPublicKeyRing publicRing);
            PgpSecretKey subkey = Subkey(secretRing);
            char[] passPhrase = "pass".ToCharArray();

            PgpSecretKey cfb = PgpSecretKey.CopyWithNewPassword(subkey, new char[0], passPhrase,
                SymmetricKeyAlgorithmTag.Aes256, Random);
            Assert.That(cfb.ExtractPrivateKey(passPhrase).Key, Is.InstanceOf<MLKem1024X448PrivateKeyParameters>());

            PgpSecretKey aead = PgpSecretKey.CopyWithNewProtection(subkey, new byte[0],
                PgpSecretKeyProtection.AeadIterated(SymmetricKeyAlgorithmTag.Aes256, AeadAlgorithmTag.Ocb,
                    HashAlgorithmTag.Sha256, 0x60, Strings.ToUtf8ByteArray("pass")), Random);
            PgpPrivateKey extracted = aead.ExtractPrivateKey(passPhrase);
            byte[] message = PgpMLKemX25519Test.Encrypt(new[]{ Subkey(publicRing) }, Content);
            Assert.That(PgpMLKemX25519Test.Decrypt(message, extracted).Content, Is.EqualTo(Content));
        }

        // The RFC 9980 messages for ML-KEM-1024+X448 keys decrypt.
        [Test]
        public void Rfc9980MessagesDecrypt()
        {
            int decrypted = 0;
            foreach (string n in new[]{ "a3", "a4", "a5", "a6", "a7" })
            {
                var secretRing = new PgpSecretKeyRing(PgpV6TestUtilities.LoadRfc9980(n + "-secret-key.asc"));
                var publicRing = new PgpPublicKeyRing(PgpV6TestUtilities.LoadRfc9980(n + "-public-key.asc"));
                if (!secretRing.GetSecretKeys().Any(k => k.PublicKey.Algorithm == PublicKeyAlgorithmTag.MLKem1024_X448))
                    continue;

                PgpSecretKey subkey = Subkey(secretRing);
                Assert.That(subkey.PublicKey.Version, Is.EqualTo(6), n);
                Assert.That(Arrays.AreEqual(Subkey(publicRing).GetFingerprint(), subkey.PublicKey.GetFingerprint()),
                    Is.True, n);

                PgpPrivateKey privateKey = subkey.ExtractPrivateKey(new char[0]);
                var derived = ((MLKem1024X448PrivateKeyParameters)privateKey.Key).GeneratePublicKey();
                var published = (MLKem1024X448PublicKeyParameters)subkey.PublicKey.GetKey();
                Assert.That(Arrays.AreEqual(derived.MLKemKey.GetEncoded(), published.MLKemKey.GetEncoded()), Is.True);

                byte[] message;
                try
                {
                    message = PgpV6TestUtilities.LoadRfc9980(n + "-message.asc");
                }
                catch (Exception)
                {
                    continue;
                }

                PgpMLKemX25519Test.Decrypted result = PgpMLKemX25519Test.Decrypt(message, privateKey,
                    publicRing.GetPublicKey());
                Assert.That(Encoding.UTF8.GetString(result.Content), Is.EqualTo("Testing\n"), n);
                Assert.That(result.IntegrityVerified, Is.True, n);
                Assert.That(result.SignatureVerified, Is.True, n);
                ++decrypted;
            }

            Assert.That(decrypted, Is.GreaterThan(0));
        }

        // The combiner of RFC 9980 4.2.1 uses algorithm ID 36 for this KEM.
        [Test]
        public void CombinerUsesAlgorithmId()
        {
            byte[] mlkem = Hex.Decode("0102030405060708091011121314151617181920212223242526272829303132");
            byte[] ecdh = new byte[56];
            byte[] ct = new byte[56];
            byte[] pk = new byte[56];

            byte[] kek = PgpCompositeKem.MLKem1024X448.MultiKeyCombine(mlkem, ecdh, ct, pk);
            Assert.That(kek, Is.EqualTo(PgpCompositeKem.MultiKeyCombine(mlkem, ecdh, ct, pk, 36)));
            Assert.That(kek, Is.Not.EqualTo(PgpCompositeKem.MultiKeyCombine(mlkem, ecdh, ct, pk, 35)));
            Assert.That(kek.Length, Is.EqualTo(32));
        }
    }
}
