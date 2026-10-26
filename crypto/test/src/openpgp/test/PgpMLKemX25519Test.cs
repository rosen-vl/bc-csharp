using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Bcpg.Sig;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    /// <summary>
    /// Tests for the RFC 9980 ML-KEM-768+X25519 composite KEM (algorithm ID 35) on v4 subkeys, including the
    /// RFC 9980 Appendix A.2 test vectors.
    /// </summary>
    [TestFixture]
    public class PgpMLKemX25519Test
    {
        private static readonly SecureRandom Random = new SecureRandom();

        private static readonly DateTime KeyTime = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        private const string A2PrimaryFingerprint = "342e5db2de345215cb2c944f7102ffed3b9cf12d";
        private const string A2SubkeyFingerprint = "e51dbfea51936988b5428fffa4f95f985ed61a51";
        internal static readonly long A2SubkeyId = unchecked((long)0xa4f95f985ed61a51UL);

        private static PublicKeyPacket ReadKeyPacket(byte[] encoded) =>
            (PublicKeyPacket)BcpgInputStream.Wrap(new MemoryStream(encoded, false)).ReadPacket();

        /// <summary>Load an RFC 9980 Appendix A.2 test vector and return its de-armored bytes.</summary>
        internal static byte[] LoadA2(string name)
        {
            using (var armored = new ArmoredInputStream(SimpleTest.GetTestDataAsStream("openpgp.rfc9980." + name)))
            {
                return Streams.ReadAll(armored);
            }
        }

        internal static PgpPublicKeyRing A2PublicRing() => new PgpPublicKeyRing(LoadA2("a2-public-key.asc"));

        internal static PgpSecretKeyRing A2SecretRing() => new PgpSecretKeyRing(LoadA2("a2-secret-key.asc"));

        internal static PgpPublicKey A2Subkey(PgpPublicKeyRing ring) => ring.GetPublicKey(A2SubkeyId);

        [Test]
        public void A2KeyRingsLoad()
        {
            PgpPublicKeyRing pubRing = A2PublicRing();
            PgpPublicKey primary = pubRing.GetPublicKey();
            PgpPublicKey subkey = A2Subkey(pubRing);

            Assert.That(Hex.ToHexString(primary.GetFingerprint()), Is.EqualTo(A2PrimaryFingerprint));
            Assert.That(primary.Algorithm, Is.EqualTo(PublicKeyAlgorithmTag.Ed25519));
            Assert.That(subkey, Is.Not.Null);
            Assert.That(Hex.ToHexString(subkey.GetFingerprint()), Is.EqualTo(A2SubkeyFingerprint));
            Assert.That(subkey.Algorithm, Is.EqualTo(PublicKeyAlgorithmTag.MLKem768_X25519));

            PgpSecretKeyRing secRing = A2SecretRing();
            Assert.That(secRing.GetSecretKey(A2SubkeyId), Is.Not.Null);
            Assert.That(Hex.ToHexString(secRing.GetSecretKey().PublicKey.GetFingerprint()),
                Is.EqualTo(A2PrimaryFingerprint));
        }

        [Test]
        public void A2KeyRingsReencode()
        {
            Assert.That(Arrays.AreEqual(LoadA2("a2-public-key.asc"), A2PublicRing().GetEncoded()), Is.True);
            Assert.That(Arrays.AreEqual(LoadA2("a2-secret-key.asc"), A2SecretRing().GetEncoded()), Is.True);
        }

        [Test]
        public void A2Ed25519SignaturesVerify()
        {
            PgpPublicKeyRing ring = A2PublicRing();
            PgpPublicKey primary = ring.GetPublicKey();
            PgpPublicKey subkey = A2Subkey(ring);

            string userId = primary.GetUserIds().First();
            PgpSignature certification = primary.GetSignaturesForId(userId).First();
            Assert.That(certification.KeyAlgorithm, Is.EqualTo(PublicKeyAlgorithmTag.Ed25519));
            certification.InitVerify(primary);
            Assert.That(certification.VerifyCertification(userId, primary), Is.True);

            PgpSignature binding = subkey.GetSignaturesOfType(PgpSignature.SubkeyBinding).First();
            binding.InitVerify(primary);
            Assert.That(binding.VerifyCertification(primary, subkey), Is.True);

            Assert.That(subkey.GetValidSeconds(), Is.EqualTo(0L));
            Assert.That(A2SecretRing().GetSecretKey().IsSigningKey, Is.True);
        }

        [Test]
        public void EdDsaMinimumHashSize()
        {
            bool StrongEnough(PublicKeyAlgorithmTag keyAlgorithm, HashAlgorithmTag hashAlgorithm) =>
                PgpUtilities.IsHashStrongEnough(keyAlgorithm, hashAlgorithm);

            Assert.That(StrongEnough(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha1), Is.False);
            Assert.That(StrongEnough(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha224), Is.False);
            Assert.That(StrongEnough(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha256), Is.True);
            Assert.That(StrongEnough(PublicKeyAlgorithmTag.Ed448, HashAlgorithmTag.Sha256), Is.False);
            Assert.That(StrongEnough(PublicKeyAlgorithmTag.Ed448, HashAlgorithmTag.Sha384), Is.False);
            Assert.That(StrongEnough(PublicKeyAlgorithmTag.Ed448, HashAlgorithmTag.Sha512), Is.True);

            // RFC 9580 5.2.3.3
            Assert.That(StrongEnough(PublicKeyAlgorithmTag.EdDsa_Legacy, HashAlgorithmTag.Sha1), Is.False);
            Assert.That(StrongEnough(PublicKeyAlgorithmTag.EdDsa_Legacy, HashAlgorithmTag.Sha224), Is.False);
            Assert.That(StrongEnough(PublicKeyAlgorithmTag.EdDsa_Legacy, HashAlgorithmTag.Sha256), Is.True);

            // Unchanged for other algorithms
            Assert.That(StrongEnough(PublicKeyAlgorithmTag.RsaGeneral, HashAlgorithmTag.Sha1), Is.True);
        }

        /// <summary>
        /// Generate a v4 key ring following the recommended recipe: EdDSA (legacy) primary key and an
        /// ML-KEM-768+X25519 encryption subkey, advertising only v1 SEIPD.
        /// </summary>
        internal static PgpSecretKeyRing GenerateRing(string userId, char[] passPhrase,
            out PgpPublicKeyRing publicRing)
        {
            var edGen = new Ed25519KeyPairGenerator();
            edGen.Init(new Ed25519KeyGenerationParameters(Random));
            var primary = new PgpKeyPair(PublicKeyAlgorithmTag.EdDsa_Legacy, edGen.GenerateKeyPair(), DateTime.UtcNow);

            var hashed = new PgpSignatureSubpacketGenerator();
            hashed.SetKeyFlags(false, PgpKeyFlags.CanCertify | PgpKeyFlags.CanSign);
            hashed.SetFeature(false, Features.FEATURE_MODIFICATION_DETECTION);
            hashed.SetPreferredSymmetricAlgorithms(false,
                new int[]{ (int)SymmetricKeyAlgorithmTag.Aes256, (int)SymmetricKeyAlgorithmTag.Aes128 });
            hashed.SetPreferredHashAlgorithms(false,
                new int[]{ (int)HashAlgorithmTag.Sha512, (int)HashAlgorithmTag.Sha256 });
            hashed.SetIssuerFingerprint(false, primary.PublicKey);

            // Unprotected keys must use the Null algorithm: AES-256 with an empty passphrase still encrypts the key
            var encAlgorithm = passPhrase == null ? SymmetricKeyAlgorithmTag.Null : SymmetricKeyAlgorithmTag.Aes256;
            var krg = new PgpKeyRingGenerator(PgpSignature.PositiveCertification, primary, userId, encAlgorithm,
                HashAlgorithmTag.Sha512, passPhrase ?? new char[0], true, hashed.Generate(), null, Random);

            var subPrivate = new MLKem768X25519PrivateKeyParameters(Random);
            var subKeyPair = new PgpKeyPair(PublicKeyAlgorithmTag.MLKem768_X25519, subPrivate.GeneratePublicKey(),
                subPrivate, DateTime.UtcNow);

            var subHashed = new PgpSignatureSubpacketGenerator();
            subHashed.SetKeyFlags(false, PgpKeyFlags.CanEncryptCommunications | PgpKeyFlags.CanEncryptStorage);
            subHashed.SetIssuerFingerprint(false, primary.PublicKey);
            krg.AddSubKey(subKeyPair, subHashed.Generate(), null, HashAlgorithmTag.Sha256);

            publicRing = krg.GeneratePublicKeyRing();
            return krg.GenerateSecretKeyRing();
        }

        internal static PgpPublicKey MLKemSubkey(PgpPublicKeyRing ring) =>
            ring.GetPublicKeys().First(k => k.Algorithm == PublicKeyAlgorithmTag.MLKem768_X25519);

        internal static PgpSecretKey MLKemSubkey(PgpSecretKeyRing ring) =>
            ring.GetSecretKeys().First(k => k.PublicKey.Algorithm == PublicKeyAlgorithmTag.MLKem768_X25519);

        internal static PgpKeyPair NewMLKemKeyPair()
        {
            var privateKey = new MLKem768X25519PrivateKeyParameters(Random);
            return new PgpKeyPair(PublicKeyAlgorithmTag.MLKem768_X25519, privateKey.GeneratePublicKey(), privateKey,
                DateTime.UtcNow);
        }

        internal static PgpKeyPair NewEdDsaKeyPair()
        {
            var edGen = new Ed25519KeyPairGenerator();
            edGen.Init(new Ed25519KeyGenerationParameters(Random));
            return new PgpKeyPair(PublicKeyAlgorithmTag.EdDsa_Legacy, edGen.GenerateKeyPair(), DateTime.UtcNow);
        }

        [Test]
        public void A2SubkeyPrivateKeyExtracts()
        {
            PgpPublicKey subkey = A2Subkey(A2PublicRing());
            Assert.That(subkey.IsEncryptionKey, Is.True);
            Assert.That(subkey.IsMasterKey, Is.False);

            var publicParams = (MLKem768X25519PublicKeyParameters)subkey.GetKey();
            PgpPrivateKey privateKey = A2SecretRing().GetSecretKey(A2SubkeyId).ExtractPrivateKey(new char[0]);
            var privateParams = (MLKem768X25519PrivateKeyParameters)privateKey.Key;
            MLKem768X25519PublicKeyParameters derived = privateParams.GeneratePublicKey();

            Assert.That(Arrays.AreEqual(publicParams.X25519Key.GetEncoded(), derived.X25519Key.GetEncoded()), Is.True);
            Assert.That(Arrays.AreEqual(publicParams.MLKemKey.GetEncoded(), derived.MLKemKey.GetEncoded()), Is.True);
        }

        [Test]
        public void CorruptedSeedRejected()
        {
            byte[] encoded = LoadA2("a2-secret-key.asc");
            byte[] material = ((MLKem768X25519PublicBcpgKey)A2Subkey(A2PublicRing()).PublicKeyPacket.Key).GetKey();

            // secret subkey packet: ... public material | S2K usage | X25519 secret (32) | ML-KEM seed (64) | checksum
            int materialPos = IndexOf(encoded, material);
            Assert.That(materialPos, Is.GreaterThan(0));
            encoded[materialPos + material.Length + 1 + 32 + 5] ^= 0x01;

            PgpSecretKey corrupted = new PgpSecretKeyRing(encoded).GetSecretKey(A2SubkeyId);
            Assert.Throws<PgpException>(() => corrupted.ExtractPrivateKey(new char[0]));
        }

        private static int IndexOf(byte[] data, byte[] pattern)
        {
            for (int i = 0; i + pattern.Length <= data.Length; ++i)
            {
                if (Arrays.AreEqual(pattern, 0, pattern.Length, data, i, i + pattern.Length))
                    return i;
            }
            return -1;
        }

        [Test]
        public void GeneratedKeyRingRoundTrip()
        {
            foreach (char[] passPhrase in new char[][]{ null, "passphrase".ToCharArray() })
            {
                PgpSecretKeyRing secretRing = GenerateRing("test <test@example.org>", passPhrase,
                    out PgpPublicKeyRing publicRing);

                var reparsedPublic = new PgpPublicKeyRing(publicRing.GetEncoded());
                var reparsedSecret = new PgpSecretKeyRing(secretRing.GetEncoded());
                Assert.That(Arrays.AreEqual(publicRing.GetEncoded(), reparsedPublic.GetEncoded()), Is.True);
                Assert.That(Arrays.AreEqual(secretRing.GetEncoded(), reparsedSecret.GetEncoded()), Is.True);

                PgpPublicKey primary = reparsedPublic.GetPublicKey();
                PgpPublicKey subkey = MLKemSubkey(reparsedPublic);
                Assert.That(subkey.IsEncryptionKey, Is.True);
                Assert.That(subkey.IsMasterKey, Is.False);

                PgpSignature binding = subkey.GetSignaturesOfType(PgpSignature.SubkeyBinding).First();
                Assert.That(binding.HashAlgorithm, Is.EqualTo(HashAlgorithmTag.Sha256));
                binding.InitVerify(primary);
                Assert.That(binding.VerifyCertification(primary, subkey), Is.True);

                PgpSecretKey secretSubkey = MLKemSubkey(reparsedSecret);
                int expectedUsage = passPhrase == null ? SecretKeyPacket.UsageNone : SecretKeyPacket.UsageSha1;
                Assert.That(secretSubkey.S2kUsage, Is.EqualTo(expectedUsage));
                Assert.That(secretSubkey.ExtractPrivateKey(passPhrase ?? new char[0]).Key,
                    Is.InstanceOf<MLKem768X25519PrivateKeyParameters>());
            }
        }

        [Test]
        public void ProtectedSubkeyPasswordChange()
        {
            PgpSecretKeyRing secretRing = GenerateRing("test", "old".ToCharArray(), out _);
            PgpSecretKey subkey = MLKemSubkey(secretRing);

            PgpSecretKey changed = PgpSecretKey.CopyWithNewPassword(subkey, "old".ToCharArray(), "new".ToCharArray(),
                SymmetricKeyAlgorithmTag.Aes256, Random);
            Assert.That(changed.ExtractPrivateKey("new".ToCharArray()).Key,
                Is.InstanceOf<MLKem768X25519PrivateKeyParameters>());

            PgpSecretKey unprotected = PgpSecretKey.CopyWithNewPassword(subkey, "old".ToCharArray(), null,
                SymmetricKeyAlgorithmTag.Null, Random);
            Assert.That(unprotected.ExtractPrivateKey(null).Key, Is.InstanceOf<MLKem768X25519PrivateKeyParameters>());
        }

        [Test]
        public void KeyParameterValidation()
        {
            var x25519Public = new X25519PrivateKeyParameters(Random).GeneratePublicKey();
            Assert.Throws<ArgumentException>(
                () => new PgpPublicKey(PublicKeyAlgorithmTag.MLKem768_X25519, x25519Public, DateTime.UtcNow));

            var composite = new MLKem768X25519PrivateKeyParameters(Random).GeneratePublicKey();
            Assert.Throws<ArgumentException>(
                () => new PgpPublicKey(PublicKeyAlgorithmTag.ECDH, composite, DateTime.UtcNow));

            // ML-KEM keys loaded from an expanded encoding have no seed, which OpenPGP requires
            var seeded = new MLKem768X25519PrivateKeyParameters(Random);
            var noSeed = MLKemPrivateKeyParameters.FromEncoding(MLKemParameters.ml_kem_768,
                seeded.MLKemKey.GetEncoded());
            Assert.Throws<ArgumentException>(
                () => new MLKem768X25519PrivateKeyParameters(seeded.X25519Key, noSeed));

            var gen = new MLKemKeyPairGenerator();
            gen.Init(new MLKemKeyGenerationParameters(Random, MLKemParameters.ml_kem_512));
            var mlKem512 = (MLKemPrivateKeyParameters)gen.GenerateKeyPair().Private;
            Assert.Throws<ArgumentException>(
                () => new MLKem768X25519PrivateKeyParameters(seeded.X25519Key, mlKem512));
        }

        [Test]
        public void KeyRingGeneratorRules()
        {
            Assert.Throws<ArgumentException>(() => new PgpKeyRingGenerator(PgpSignature.PositiveCertification,
                NewMLKemKeyPair(), "test", SymmetricKeyAlgorithmTag.Null, HashAlgorithmTag.Sha256, new char[0], false,
                null, null, Random));

            var krg = new PgpKeyRingGenerator(PgpSignature.PositiveCertification, NewEdDsaKeyPair(), "test",
                SymmetricKeyAlgorithmTag.Null, HashAlgorithmTag.Sha256, new char[0], false, null, null, Random);

            Assert.Throws<ArgumentException>(() => krg.AddSubKey(NewMLKemKeyPair(), null, null, HashAlgorithmTag.Sha1));
            Assert.Throws<ArgumentException>(
                () => krg.AddSubKey(NewMLKemKeyPair(), HashAlgorithmTag.Sha256, HashAlgorithmTag.Sha256));

            // The overload that defaults to SHA-1 uses SHA-256 for ML-KEM-768+X25519 subkeys
            krg.AddSubKey(NewMLKemKeyPair());
            PgpPublicKey subkey = MLKemSubkey(krg.GeneratePublicKeyRing());
            Assert.That(subkey.GetSignaturesOfType(PgpSignature.SubkeyBinding).First().HashAlgorithm,
                Is.EqualTo(HashAlgorithmTag.Sha256));
        }

        [Test]
        public void SubkeyBindingHashRules()
        {
            PgpKeyPair master = NewEcdsaKeyPair();
            PgpKeyPair sub = NewMLKemKeyPair();

            PgpSignatureGenerator Generator(int signatureType, HashAlgorithmTag hashAlgorithm)
            {
                var sGen = new PgpSignatureGenerator(PublicKeyAlgorithmTag.ECDsa, hashAlgorithm);
                sGen.InitSign(signatureType, master.PrivateKey);
                return sGen;
            }

            bool Verify(PgpSignature signature)
            {
                signature.InitVerify(master.PublicKey);
                return signature.VerifyCertification(master.PublicKey, sub.PublicKey);
            }

            Assert.That(Verify(Generator(PgpSignature.SubkeyBinding, HashAlgorithmTag.Sha256)
                .GenerateCertification(master.PublicKey, sub.PublicKey)), Is.True);

            // RFC 9580 9.5: the generator refuses SHA-1 for any new signature
            Assert.Throws<PgpException>(() => Generator(PgpSignature.SubkeyBinding, HashAlgorithmTag.Sha1));

            // RFC 9980 7.2: a SHA-1 binding made all the same does not verify
            Assert.That(Verify(SignKeysDirectly(master, PgpSignature.SubkeyBinding, HashAlgorithmTag.Sha1,
                master.PublicKey, sub.PublicKey)), Is.False);

            // it restricts binding signatures only; old revocations verify as before
            Assert.That(Verify(SignKeysDirectly(master, PgpSignature.SubkeyRevocation, HashAlgorithmTag.Sha1,
                master.PublicKey, sub.PublicKey)), Is.True);
        }

        /// <summary>
        /// A version 4 signature over two keys, made with the signer of the library itself so that it can use a hash
        /// that the signature generator refuses.
        /// </summary>
        internal static PgpSignature SignKeysDirectly(PgpKeyPair signer, int signatureType,
            HashAlgorithmTag hashAlgorithm, PgpPublicKey masterKey, PgpPublicKey subkey)
        {
            PublicKeyAlgorithmTag algorithm = signer.PublicKey.Algorithm;
            SignatureSubpacket[] hashed = { new SignatureCreationTime(false, DateTime.UtcNow) };
            var unhashed = new SignatureSubpacket[0];
            byte[] trailer = new SignaturePacket(signatureType, signer.KeyId, algorithm, hashAlgorithm, hashed,
                unhashed, new byte[2], new MPInteger[0]).GetSignatureTrailer();

            var bOut = new MemoryStream();
            foreach (PgpPublicKey key in new[]{ masterKey, subkey })
            {
                byte[] body = key.PublicKeyPacket.GetEncodedContents();
                bOut.WriteByte(0x99);
                bOut.WriteByte((byte)(body.Length >> 8));
                bOut.WriteByte((byte)body.Length);
                bOut.Write(body, 0, body.Length);
            }
            bOut.Write(trailer, 0, trailer.Length);
            byte[] data = bOut.ToArray();

            ISigner raw = PgpUtilities.CreateSigner(algorithm, hashAlgorithm, signer.PrivateKey.Key);
            raw.Init(true, new ParametersWithRandom(signer.PrivateKey.Key, Random));
            raw.BlockUpdate(data, 0, data.Length);
            byte[] hashValue = DigestUtilities.DoFinal(PgpUtilities.CreateDigest(hashAlgorithm), data);

            return new PgpSignature(new SignaturePacket(signatureType, signer.KeyId, algorithm, hashAlgorithm,
                hashed, unhashed, new byte[]{ hashValue[0], hashValue[1] },
                PgpUtilities.DsaSigToMpi(raw.GenerateSignature())));
        }

        internal static PgpKeyPair NewEcdsaKeyPair()
        {
            var generator = new ECKeyPairGenerator();
            generator.Init(new ECKeyGenerationParameters(SecObjectIdentifiers.SecP256r1, Random));
            return new PgpKeyPair(PublicKeyAlgorithmTag.ECDsa, generator.GenerateKeyPair(), DateTime.UtcNow);
        }

        /// <summary>
        /// Hash a key into a signature the way that a certification of keys does, so that a binding can be made without
        /// the checks of <see cref="PgpSignatureGenerator.GenerateCertification(PgpPublicKey, PgpPublicKey)"/>.
        /// </summary>
        internal static void UpdateWithKey(PgpSignatureGenerator generator, PgpPublicKey key, int signatureVersion = 4)
        {
            byte[] body = key.PublicKeyPacket.GetEncodedContents();
            if (signatureVersion == 6)
            {
                generator.Update(0x9B, (byte)(body.Length >> 24), (byte)(body.Length >> 16), (byte)(body.Length >> 8),
                    (byte)body.Length);
            }
            else
            {
                generator.Update(0x99, (byte)(body.Length >> 8), (byte)body.Length);
            }
            generator.Update(body);
        }

        internal sealed class Decrypted
        {
            internal byte[] Content;
            internal bool IntegrityVerified;
            internal SymmetricKeyAlgorithmTag Algorithm;
            internal int OnePassSignatureCount;
            internal int SignatureCount;
            internal bool? SignatureVerified;
        }

        internal static byte[] Encrypt(IEnumerable<PgpPublicKey> recipients, byte[] content,
            SymmetricKeyAlgorithmTag algorithm = SymmetricKeyAlgorithmTag.Aes256, bool armor = false,
            PgpSecretKey signer = null, char[] passPhrase = null, bool compress = false)
        {
            var bOut = new MemoryStream();
            Stream outStr = armor ? (Stream)new ArmoredOutputStream(bOut) : bOut;

            var encGen = new PgpEncryptedDataGenerator(algorithm, true, Random);
            foreach (var recipient in recipients)
            {
                encGen.AddMethod(recipient);
            }
            if (passPhrase != null)
            {
                encGen.AddMethod(passPhrase, HashAlgorithmTag.Sha256);
            }

            using (Stream encOut = encGen.Open(outStr, new byte[1 << 12]))
            {
                var compGen = compress ? new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip) : null;
                Stream dataOut = compress ? compGen.Open(encOut) : encOut;

                PgpSignatureGenerator sigGen = null;
                if (signer != null)
                {
                    sigGen = new PgpSignatureGenerator(signer.PublicKey.Algorithm, HashAlgorithmTag.Sha512);
                    sigGen.InitSign(PgpSignature.BinaryDocument, signer.ExtractPrivateKey(new char[0]));
                    sigGen.GenerateOnePassVersion(false).Encode(dataOut);
                }

                using (var litOut = new PgpLiteralDataGenerator().Open(dataOut, PgpLiteralData.Binary, "",
                    content.Length, DateTime.UtcNow))
                {
                    litOut.Write(content, 0, content.Length);
                }

                if (sigGen != null)
                {
                    sigGen.Update(content);
                    sigGen.Generate().Encode(dataOut);
                }

                compGen?.Close();
            }

            if (armor)
            {
                outStr.Dispose();
            }
            return bOut.ToArray();
        }

        internal static PgpPublicKeyEncryptedData FindEncryptedData(byte[] message, long keyId)
        {
            var factory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(new MemoryStream(message, false)));
            var encList = (PgpEncryptedDataList)factory.NextPgpObject();
            var candidates = encList.GetEncryptedDataObjects().OfType<PgpPublicKeyEncryptedData>().ToList();

            // Prefer the PKESK addressed to the key, then an anonymous one (key ID zero)
            return candidates.FirstOrDefault(d => d.KeyId == keyId) ?? candidates.First(d => d.KeyId == 0);
        }

        internal static Decrypted Decrypt(byte[] message, PgpPrivateKey privateKey, PgpPublicKey verifyKey = null)
        {
            PgpPublicKeyEncryptedData encData = FindEncryptedData(message, privateKey.KeyId);
            return ReadContent(encData, encData.GetDataStream(privateKey), verifyKey,
                encData.GetSymmetricAlgorithm(privateKey));
        }

        internal static Decrypted ReadContent(PgpEncryptedData encData, Stream clear, PgpPublicKey verifyKey,
            SymmetricKeyAlgorithmTag algorithm)
        {
            var result = new Decrypted{ Algorithm = algorithm };
            var factory = new PgpObjectFactory(clear);
            PgpOnePassSignature onePass = null;

            PgpObject obj;
            while ((obj = factory.NextPgpObject()) != null)
            {
                if (obj is PgpCompressedData compressed)
                {
                    factory = new PgpObjectFactory(compressed.GetDataStream());
                }
                else if (obj is PgpOnePassSignatureList onePassList)
                {
                    result.OnePassSignatureCount = onePassList.Count;
                    if (verifyKey != null && onePassList.Count > 0)
                    {
                        onePass = onePassList[0];
                        onePass.InitVerify(verifyKey);
                    }
                }
                else if (obj is PgpLiteralData literal)
                {
                    result.Content = Streams.ReadAll(literal.GetDataStream());
                    onePass?.Update(result.Content);
                }
                else if (obj is PgpSignatureList sigList)
                {
                    result.SignatureCount = sigList.Count;
                    if (onePass != null && sigList.Count > 0)
                    {
                        result.SignatureVerified = onePass.Verify(sigList[0]);
                    }
                }
            }

            // The integrity check is only performed when the caller asks for it, after reading all the data
            result.IntegrityVerified = encData.Verify();
            return result;
        }

        private static byte[] RandomBytes(int length) => SecureRandom.GetNextBytes(Random, length);

        [Test]
        public void MultiKeyCombineKnownAnswer()
        {
            byte[] message = LoadA2("a2-seipdv1-message.asc");
            var pkesk = (PublicKeyEncSessionPacket)BcpgInputStream.Wrap(new MemoryStream(message, false)).ReadPacket();
            byte[] ecdhCipherText = Arrays.CopyOfRange(pkesk.GetEncSessionKey()[0], 0, 32);
            byte[] ecdhPublicKey = ((MLKem768X25519PublicBcpgKey)A2Subkey(A2PublicRing()).PublicKeyPacket.Key)
                .GetX25519PublicKey();

            byte[] kek = PgpMLKemX25519.MultiKeyCombine(
                Hex.Decode("16f2aea8ec1ca277c04cc7b87681d7d38511a38f554775a8fc4de41aa76eb586"),
                Hex.Decode("2fc0c8fcace9636c86d1ee1715a302819ad48c549579a462a33eed36627c532e"),
                ecdhCipherText, ecdhPublicKey, (byte)PublicKeyAlgorithmTag.MLKem768_X25519);

            Assert.That(Hex.ToHexString(kek),
                Is.EqualTo("c1591d7511f9f0213bfd57cf316e5ec0d40c4ea826fa989ab606aa3b8a1a2c1f"));
        }

        [Test]
        public void A2SeipdV1MessageDecrypts()
        {
            PgpPublicKeyRing publicRing = A2PublicRing();
            PgpPrivateKey privateKey = A2SecretRing().GetSecretKey(A2SubkeyId).ExtractPrivateKey(new char[0]);

            Decrypted result = Decrypt(LoadA2("a2-seipdv1-message.asc"), privateKey, publicRing.GetPublicKey());

            Assert.That(Encoding.UTF8.GetString(result.Content), Is.EqualTo("Testing\n"));
            Assert.That(result.Algorithm, Is.EqualTo(SymmetricKeyAlgorithmTag.Aes256));
            Assert.That(result.SignatureVerified, Is.True);
            Assert.That(result.IntegrityVerified, Is.True);
        }

        [Test]
        public void EncryptDecryptRoundTrip()
        {
            PgpSecretKeyRing secretRing = GenerateRing("test", null, out PgpPublicKeyRing publicRing);
            var recipient = new PgpPublicKeyRing(publicRing.GetEncoded());
            PgpPrivateKey privateKey = MLKemSubkey(secretRing).ExtractPrivateKey(new char[0]);

            foreach (var algorithm in new[]{ SymmetricKeyAlgorithmTag.Aes128, SymmetricKeyAlgorithmTag.Aes192,
                SymmetricKeyAlgorithmTag.Aes256 })
            {
                foreach (int length in new[]{ 0, 1, 70000 })
                {
                    byte[] content = RandomBytes(length);
                    byte[] message = Encrypt(new[]{ MLKemSubkey(recipient) }, content, algorithm, armor: length == 1);

                    Decrypted result = Decrypt(message, privateKey);

                    Assert.That(Arrays.AreEqual(content, result.Content), Is.True);
                    Assert.That(result.Algorithm, Is.EqualTo(algorithm));
                    Assert.That(result.IntegrityVerified, Is.True);
                }
            }

            // Partial-length packets, several MiB
            byte[] large = RandomBytes(3 * 1024 * 1024 + 7);
            Decrypted largeResult = Decrypt(Encrypt(new[]{ MLKemSubkey(recipient) }, large), privateKey);
            Assert.That(Arrays.AreEqual(large, largeResult.Content), Is.True);
            Assert.That(largeResult.IntegrityVerified, Is.True);

            // A subkey taken from a freshly generated secret ring (before any re-parse) can be encrypted to
            byte[] fresh = Encrypt(new[]{ MLKemSubkey(secretRing).PublicKey }, new byte[]{ 1, 2, 3 });
            Assert.That(Arrays.AreEqual(new byte[]{ 1, 2, 3 }, Decrypt(fresh, privateKey).Content), Is.True);
        }

        [Test]
        public void MixedRecipients()
        {
            PgpSecretKeyRing pqSecret = GenerateRing("pq", null, out PgpPublicKeyRing pqPublic);
            PgpSecretKeyRing rsaSecret = PgpUnsupportedVersionTest.GenerateRsaRing(out PgpPublicKeyRing rsaPublic);

            var xGen = new X25519KeyPairGenerator();
            xGen.Init(new X25519KeyGenerationParameters(Random));
            var ecdhKeyPair = new PgpKeyPair(PublicKeyAlgorithmTag.ECDH, xGen.GenerateKeyPair(), DateTime.UtcNow);
            var ecdhGen = new PgpKeyRingGenerator(PgpSignature.PositiveCertification, NewEdDsaKeyPair(), "ecdh",
                SymmetricKeyAlgorithmTag.Null, HashAlgorithmTag.Sha256, new char[0], false, null, null, Random);
            ecdhGen.AddSubKey(ecdhKeyPair, HashAlgorithmTag.Sha256);
            PgpSecretKeyRing ecdhSecret = ecdhGen.GenerateSecretKeyRing();
            PgpPublicKey ecdhSubkey = ecdhGen.GeneratePublicKeyRing().GetPublicKeys().Last();

            byte[] content = Encoding.UTF8.GetBytes("for several recipients");
            char[] passPhrase = "passphrase".ToCharArray();
            byte[] message = Encrypt(new[]{ MLKemSubkey(pqPublic), rsaPublic.GetPublicKey(), ecdhSubkey }, content,
                passPhrase: passPhrase);

            var privateKeys = new[]{
                MLKemSubkey(pqSecret).ExtractPrivateKey(new char[0]),
                rsaSecret.GetSecretKey().ExtractPrivateKey(new char[0]),
                ecdhSecret.GetSecretKey(ecdhSubkey.KeyId).ExtractPrivateKey(new char[0]),
            };
            foreach (PgpPrivateKey privateKey in privateKeys)
            {
                Decrypted result = Decrypt(message, privateKey);
                Assert.That(Arrays.AreEqual(content, result.Content), Is.True);
                Assert.That(result.IntegrityVerified, Is.True);
            }

            var encList = (PgpEncryptedDataList)new PgpObjectFactory(message).NextPgpObject();
            PgpPbeEncryptedData pbeData = encList.GetEncryptedDataObjects().OfType<PgpPbeEncryptedData>().Single();
            Decrypted pbeResult = ReadContent(pbeData, pbeData.GetDataStream(passPhrase), null,
                SymmetricKeyAlgorithmTag.Aes256);
            Assert.That(Arrays.AreEqual(content, pbeResult.Content), Is.True);
            Assert.That(pbeResult.IntegrityVerified, Is.True);
        }

        [Test]
        public void CompressedAndSignedContent()
        {
            PgpSecretKeyRing secretRing = GenerateRing("test", null, out PgpPublicKeyRing publicRing);
            PgpPrivateKey privateKey = MLKemSubkey(secretRing).ExtractPrivateKey(new char[0]);
            byte[] content = Encoding.UTF8.GetBytes("compressed and signed");

            byte[] message = Encrypt(new[]{ MLKemSubkey(publicRing) }, content, signer: secretRing.GetSecretKey(),
                compress: true);
            Decrypted result = Decrypt(message, privateKey, publicRing.GetPublicKey());

            Assert.That(Arrays.AreEqual(content, result.Content), Is.True);
            Assert.That(result.SignatureVerified, Is.True);
            Assert.That(result.IntegrityVerified, Is.True);
        }

        [Test]
        public void MessageFromSignerOfUnsupportedVersion()
        {
            PgpSecretKeyRing secretRing = GenerateRing("test", null, out PgpPublicKeyRing publicRing);
            PgpPrivateKey privateKey = MLKemSubkey(secretRing).ExtractPrivateKey(new char[0]);

            // one-pass signature and signature of an unsupported version, around literal data
            var ops = new MemoryStream();
            ops.Write(new byte[]{ 7, 0x00, (byte)HashAlgorithmTag.Sha512, 30, 32 }, 0, 5);
            ops.Write(new byte[64], 0, 64);
            ops.WriteByte(1);
            byte[] content = Encoding.ASCII.GetBytes("signed by a v6 key");
            var lit = new MemoryStream();
            lit.Write(new byte[]{ (byte)'b', 0, 0, 0, 0, 0 }, 0, 6);
            lit.Write(content, 0, content.Length);
            var sig = new MemoryStream();
            sig.Write(new byte[]{ 7, 0x00, 30, (byte)HashAlgorithmTag.Sha512, 0, 0, 0, 0, 0, 0, 0, 0, 0x12, 0x34, 16 },
                0, 15);
            sig.Write(new byte[96], 0, 96);
            byte[] inner = Arrays.ConcatenateAll(
                PgpUnsupportedVersionTest.NewFormatPacket(PacketTag.OnePassSignature, ops.ToArray()),
                PgpUnsupportedVersionTest.NewFormatPacket(PacketTag.LiteralData, lit.ToArray()),
                PgpUnsupportedVersionTest.NewFormatPacket(PacketTag.Signature, sig.ToArray()));

            var bOut = new MemoryStream();
            var encGen = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, true, Random);
            encGen.AddMethod(MLKemSubkey(publicRing));
            using (Stream encOut = encGen.Open(bOut, new byte[1 << 10]))
            {
                encOut.Write(inner, 0, inner.Length);
            }

            Decrypted result = Decrypt(bOut.ToArray(), privateKey);
            Assert.That(Arrays.AreEqual(content, result.Content), Is.True);
            Assert.That(result.OnePassSignatureCount, Is.EqualTo(0));
            Assert.That(result.SignatureCount, Is.EqualTo(0));
            Assert.That(result.IntegrityVerified, Is.True);
        }

        [Test]
        public void CraftedPacketSequences()
        {
            PgpSecretKeyRing secretRing = GenerateRing("test", null, out PgpPublicKeyRing publicRing);
            PgpPrivateKey privateKey = MLKemSubkey(secretRing).ExtractPrivateKey(new char[0]);
            byte[] content = Encoding.UTF8.GetBytes("crafted");
            byte[][] packets = PgpUnsupportedVersionTest.SplitPackets(Encrypt(new[]{ MLKemSubkey(publicRing) },
                content));

            // A PKESK for an unsupported algorithm (native X25519) and one of an unsupported version (v7) first
            byte[] x25519Body = new byte[1 + 8 + 1 + 32 + 1 + 1 + 24];
            x25519Body[0] = 3;
            x25519Body[9] = (byte)PublicKeyAlgorithmTag.X25519;
            x25519Body[42] = 25;
            byte[] v6Body = new byte[1 + 1 + 1 + 20 + 1 + 40];
            v6Body[0] = 7;
            v6Body[1] = 21;
            v6Body[2] = 4;
            v6Body[23] = (byte)PublicKeyAlgorithmTag.MLKem768_X25519;
            byte[] withExtra = Arrays.ConcatenateAll(
                PgpUnsupportedVersionTest.NewFormatPacket(PacketTag.PublicKeyEncryptedSession, v6Body),
                PgpUnsupportedVersionTest.NewFormatPacket(PacketTag.PublicKeyEncryptedSession, x25519Body),
                packets[0], packets[1]);
            Assert.That(Arrays.AreEqual(content, Decrypt(withExtra, privateKey).Content), Is.True);

            // Anonymous recipient: key ID of zero
            byte[] anonymous = Arrays.Concatenate(packets[0], packets[1]);
            int idPos = HeaderLength(packets[0]) + 1;
            Arrays.Fill(anonymous, idPos, idPos + 8, 0);
            PgpPublicKeyEncryptedData anonymousData = FindEncryptedData(anonymous, privateKey.KeyId);
            Assert.That(anonymousData.KeyId, Is.EqualTo(0L));
            Assert.That(Arrays.AreEqual(content, Decrypt(anonymous, privateKey).Content), Is.True);

            // Obsolete SED (packet type 9) payload after an ML-KEM-768+X25519 PKESK
            byte[] withSed = Arrays.Concatenate(packets[0],
                PgpUnsupportedVersionTest.NewFormatPacket(PacketTag.SymmetricKeyEncrypted, RandomBytes(64)));
            var e = Assert.Throws<PgpException>(
                () => FindEncryptedData(withSed, privateKey.KeyId).GetDataStream(privateKey));
            Assert.That(e.Message, Does.Contain("SEIPD"));
        }

        internal static int HeaderLength(byte[] packet)
        {
            if ((packet[0] & 0x40) == 0)
                return 1 + new[]{ 1, 2, 4, 0 }[packet[0] & 3];

            return packet[1] < 192 ? 2 : packet[1] < 224 ? 3 : 6;
        }

        [Test]
        public void EncryptionRequirements()
        {
            PgpPublicKey subkey = MLKemSubkey(A2PublicRing());

            Assert.Throws<PgpException>(() => new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256)
                .AddMethod(subkey));
            Assert.Throws<PgpException>(() => new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Camellia256, true)
                .AddMethod(subkey));

            // RFC 9980 4.3.1: a version 6 key is a valid recipient; it gets a version 3 PKESK in a version 1 message
            var v6Packet = new PublicKeyPacket(PublicKeyPacket.Version6, PublicKeyAlgorithmTag.MLKem768_X25519,
                DateTime.UtcNow, subkey.PublicKeyPacket.Key);
            Assert.DoesNotThrow(() => new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, true)
                .AddMethod(new PgpPublicKey(v6Packet)));
        }

        [Test]
        public void TamperedSessionKeyRejectedUniformly()
        {
            PgpSecretKeyRing secretRing = GenerateRing("test", null, out PgpPublicKeyRing publicRing);
            PgpPrivateKey privateKey = MLKemSubkey(secretRing).ExtractPrivateKey(new char[0]);
            byte[][] packets = PgpUnsupportedVersionTest.SplitPackets(
                Encrypt(new[]{ MLKemSubkey(publicRing) }, Encoding.UTF8.GetBytes("tamper")));
            byte[] pkesk = packets[0];
            int fields = HeaderLength(pkesk) + 10;

            byte[] Mutate(int offset, byte mask)
            {
                byte[] copy = Arrays.Clone(pkesk);
                copy[fields + offset] ^= mask;
                return Arrays.Concatenate(copy, packets[1]);
            }

            var messages = new System.Collections.Generic.HashSet<string>();
            var tampered = new[]{
                Mutate(5, 0x01),                                         // ECDH ciphertext
                Mutate(32 + 100, 0x01),                                  // ML-KEM ciphertext
                Mutate(1122 + 3, 0x01),                                  // wrapped session key
                Mutate(1121, (byte)SymmetricKeyAlgorithmTag.Aes256 ^ (byte)SymmetricKeyAlgorithmTag.Aes128),
                Mutate(1120, 0x08),                                      // length octet
            };
            foreach (byte[] message in tampered)
            {
                var e = Assert.Throws<PgpException>(() => Decrypt(message, privateKey));
                messages.Add(e.Message);
                Assert.That(e.InnerException, Is.Null);
            }

            // Wrong private key for the PKESK
            PgpPrivateKey otherKey = PgpUnsupportedVersionTest.GenerateRsaRing(out _).GetSecretKey()
                .ExtractPrivateKey(new char[0]);
            var wrongKey = Assert.Throws<PgpException>(
                () => FindEncryptedData(Arrays.Concatenate(pkesk, packets[1]), privateKey.KeyId)
                    .GetDataStream(otherKey));
            messages.Add(wrongKey.Message);

            Assert.That(messages.Count, Is.EqualTo(1), string.Join(" | ", messages));
        }

        [Test]
        public void TamperedPayloadFailsIntegrityCheck()
        {
            PgpSecretKeyRing secretRing = GenerateRing("test", null, out PgpPublicKeyRing publicRing);
            PgpPrivateKey privateKey = MLKemSubkey(secretRing).ExtractPrivateKey(new char[0]);
            byte[] message = Encrypt(new[]{ MLKemSubkey(publicRing) }, RandomBytes(100));
            message[message.Length - 30] ^= 0x01;

            bool integrityVerified;
            try
            {
                integrityVerified = Decrypt(message, privateKey).IntegrityVerified;
            }
            catch (Exception)
            {
                integrityVerified = false;
            }
            Assert.That(integrityVerified, Is.False);
        }

        [Test]
        public void SeveralMLKemRecipients()
        {
            PgpSecretKeyRing secretA = GenerateRing("a", null, out PgpPublicKeyRing publicA);
            PgpSecretKeyRing secretB = GenerateRing("b", null, out PgpPublicKeyRing publicB);
            byte[] content = RandomBytes(1000);

            // The same recipient twice is harmless: two PKESKs for the same session key
            byte[] message = Encrypt(new[]{ MLKemSubkey(publicA), MLKemSubkey(publicB), MLKemSubkey(publicA) },
                content);

            var encList = (PgpEncryptedDataList)new PgpObjectFactory(message).NextPgpObject();
            Assert.That(encList.Count, Is.EqualTo(3));

            foreach (PgpSecretKeyRing secretRing in new[]{ secretA, secretB })
            {
                Decrypted result = Decrypt(message, MLKemSubkey(secretRing).ExtractPrivateKey(new char[0]));
                Assert.That(Arrays.AreEqual(content, result.Content), Is.True);
                Assert.That(result.IntegrityVerified, Is.True);
            }
        }

        [Test]
        public void FixedLengthEncryption()
        {
            PgpSecretKeyRing secretRing = GenerateRing("test", null, out PgpPublicKeyRing publicRing);
            byte[] content = RandomBytes(5000);

            // Literal data first, then the encrypted packet with a definite length (no partial lengths)
            var literal = new MemoryStream();
            using (var litOut = new PgpLiteralDataGenerator().Open(literal, PgpLiteralData.Binary, "", content.Length,
                DateTime.UtcNow))
            {
                litOut.Write(content, 0, content.Length);
            }
            byte[] literalBytes = literal.ToArray();

            var bOut = new MemoryStream();
            var encGen = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, true, Random);
            encGen.AddMethod(MLKemSubkey(publicRing), sessionKeyObfuscation: false);
            using (Stream encOut = encGen.Open(bOut, literalBytes.Length))
            {
                encOut.Write(literalBytes, 0, literalBytes.Length);
            }

            Decrypted result = Decrypt(bOut.ToArray(), MLKemSubkey(secretRing).ExtractPrivateKey(new char[0]));
            Assert.That(Arrays.AreEqual(content, result.Content), Is.True);
            Assert.That(result.IntegrityVerified, Is.True);
        }

        [Test]
        public void SecretKeyProtectionVariants()
        {
            var cases = new[]{
                (SymmetricKeyAlgorithmTag.Aes128, false),
                (SymmetricKeyAlgorithmTag.Aes256, true),
                (SymmetricKeyAlgorithmTag.Camellia256, true),
                (SymmetricKeyAlgorithmTag.TripleDes, false),
            };
            foreach (var (encAlgorithm, useSha1) in cases)
            {
                var krg = new PgpKeyRingGenerator(PgpSignature.PositiveCertification, NewEdDsaKeyPair(), "test",
                    encAlgorithm, HashAlgorithmTag.Sha256, "secret".ToCharArray(), useSha1, null, null, Random);
                krg.AddSubKey(NewMLKemKeyPair(), null, null, HashAlgorithmTag.Sha256);
                PgpSecretKey subkey = MLKemSubkey(new PgpSecretKeyRing(krg.GenerateSecretKeyRing().GetEncoded()));

                // RFC 9580 3.7.2.1: usage 254 whatever useSha1 says, the checksum form (usage 255) is not generated
                Assert.That(subkey.S2kUsage, Is.EqualTo(SecretKeyPacket.UsageSha1), encAlgorithm.ToString());
                Assert.That(subkey.KeyEncryptionAlgorithm, Is.EqualTo(encAlgorithm));
                Assert.That(subkey.ExtractPrivateKey("secret".ToCharArray()).Key,
                    Is.InstanceOf<MLKem768X25519PrivateKeyParameters>(), encAlgorithm.ToString());
                Assert.Throws<PgpException>(() => subkey.ExtractPrivateKey("wrong".ToCharArray()),
                    encAlgorithm.ToString());
            }
        }

        [Test]
        public void KeyPairConstructionAndIdentity()
        {
            var privateKey = new MLKem768X25519PrivateKeyParameters(Random);
            var keyPair = new Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair(privateKey.GeneratePublicKey(),
                privateKey);

            var fromPair = new PgpKeyPair(PublicKeyAlgorithmTag.MLKem768_X25519, keyPair, KeyTime);
            var fromKeys = new PgpKeyPair(PublicKeyAlgorithmTag.MLKem768_X25519, privateKey.GeneratePublicKey(),
                privateKey, KeyTime);

            // Same key material and creation time give the same fingerprint and key ID
            Assert.That(Arrays.AreEqual(fromPair.PublicKey.GetFingerprint(), fromKeys.PublicKey.GetFingerprint()),
                Is.True);
            Assert.That(fromPair.KeyId, Is.EqualTo(fromKeys.KeyId));
            Assert.That(fromPair.PublicKey.Version, Is.EqualTo(PublicKeyPacket.Version4));
            Assert.That(fromPair.PublicKey.Algorithm, Is.EqualTo(PublicKeyAlgorithmTag.MLKem768_X25519));
            // the size of the elliptic curve
            Assert.That(fromPair.PublicKey.BitStrength, Is.EqualTo(256));

            // The public key round-trips through the key packet
            var roundTrip = (MLKem768X25519PublicKeyParameters)fromPair.PublicKey.GetKey();
            MLKem768X25519PublicKeyParameters original = privateKey.GeneratePublicKey();
            Assert.That(Arrays.AreEqual(original.X25519Key.GetEncoded(), roundTrip.X25519Key.GetEncoded()), Is.True);
            Assert.That(Arrays.AreEqual(original.MLKemKey.GetEncoded(), roundTrip.MLKemKey.GetEncoded()), Is.True);

            Assert.Throws<ArgumentException>(() => new PgpKeyPair(PublicKeyAlgorithmTag.MLKem768_X25519,
                privateKey.GeneratePublicKey(), privateKey.GeneratePublicKey(), KeyTime));
        }

        [Test]
        public void PublicRingFromSecretRing()
        {
            PgpSecretKeyRing secretRing = GenerateRing("test", "pw".ToCharArray(), out PgpPublicKeyRing publicRing);

            var bOut = new MemoryStream();
            foreach (PgpPublicKey publicKey in new PgpSecretKeyRing(secretRing.GetEncoded()).GetPublicKeys())
            {
                publicKey.Encode(bOut);
            }

            Assert.That(Arrays.AreEqual(publicRing.GetEncoded(), bOut.ToArray()), Is.True);
        }

        [Test]
        public void GeneratorWithoutIntegrityProtection()
        {
            PgpPublicKey subkey = MLKemSubkey(A2PublicRing());

            // The legacy-format constructor never adds an integrity packet
            var legacy = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, Random, oldFormat: true);
            var e = Assert.Throws<PgpException>(() => legacy.AddMethod(subkey));
            Assert.That(e.Message, Does.Contain("integrity"));

            // Other recipients are unaffected
            PgpUnsupportedVersionTest.GenerateRsaRing(out PgpPublicKeyRing rsaRing);
            legacy.AddMethod(rsaRing.GetPublicKey());
        }

        [Test]
        public void A2V6MessageHasV6Pkesk()
        {
            // A.2.4 uses a v6 PKESK (to a v4 key) and a v2 SEIPD
            var encList = (PgpEncryptedDataList)new PgpObjectFactory(LoadA2("a2-seipdv2-message.asc")).NextPgpObject();

            Assert.That(encList.Count, Is.EqualTo(1));
            Assert.That(((PgpPublicKeyEncryptedData)encList[0]).KeyId, Is.EqualTo(A2SubkeyId));
        }

        [Test]
        public void A2KeyRingJoinKeepsRawSignatures()
        {
            PgpPublicKeyRing ring = A2PublicRing();

            PgpPublicKeyRing joined = PgpPublicKeyRing.Join(ring, ring);

            Assert.That(Arrays.AreEqual(ring.GetEncoded(), joined.GetEncoded()), Is.True);
        }

        [Test]
        public void KeyMaterialPacketRoundTrip()
        {
            byte[] material = SecureRandom.GetNextBytes(Random, MLKem768X25519PublicBcpgKey.Length);
            var bcpgKey = new MLKem768X25519PublicBcpgKey(material);
            var packet = new PublicSubkeyPacket(PublicKeyPacket.Version4, PublicKeyAlgorithmTag.MLKem768_X25519,
                KeyTime, bcpgKey);

            byte[] encoded = packet.GetEncoded();
            var parsed = ReadKeyPacket(encoded);

            Assert.That(parsed, Is.InstanceOf<PublicSubkeyPacket>());
            Assert.That(parsed.Algorithm, Is.EqualTo(PublicKeyAlgorithmTag.MLKem768_X25519));
            var parsedKey = (MLKem768X25519PublicBcpgKey)parsed.Key;
            Assert.That(Arrays.AreEqual(material, parsedKey.GetKey()), Is.True);
            Assert.That(Arrays.AreEqual(Arrays.CopyOfRange(material, 0, 32), parsedKey.GetX25519PublicKey()), Is.True);
            Assert.That(Arrays.AreEqual(Arrays.CopyOfRange(material, 32, 1216), parsedKey.GetMLKemPublicKey()),
                Is.True);
            Assert.That(Arrays.AreEqual(encoded, parsed.GetEncoded()), Is.True);

            var v6 = new PublicKeyPacket(PublicKeyPacket.Version6, PublicKeyAlgorithmTag.MLKem768_X25519, KeyTime,
                bcpgKey);
            Assert.That(ReadKeyPacket(v6.GetEncoded()).Key, Is.InstanceOf<MLKem768X25519PublicBcpgKey>());
        }

        [Test]
        public void KeyMaterialSecretKeyComponents()
        {
            byte[] material = SecureRandom.GetNextBytes(Random, MLKem768X25519SecretBcpgKey.Length);
            var secretKey = new MLKem768X25519SecretBcpgKey(material);

            Assert.That(Arrays.AreEqual(Arrays.CopyOfRange(material, 0, 32), secretKey.GetX25519SecretKey()), Is.True);
            Assert.That(Arrays.AreEqual(Arrays.CopyOfRange(material, 32, 96), secretKey.GetMLKemSeed()), Is.True);
            Assert.Throws<ArgumentException>(() => new MLKem768X25519SecretBcpgKey(new byte[95]));
        }

        [Test]
        public void KeyMaterialOnlyDefinedForV4AndV6()
        {
            var bcpgKey = new MLKem768X25519PublicBcpgKey(new byte[MLKem768X25519PublicBcpgKey.Length]);

            // LibrePGP v5 key: not defined by RFC 9980, handled like any unknown algorithm
            var v5 = new PublicKeyPacket(PublicKeyPacket.LibrePgp5, PublicKeyAlgorithmTag.MLKem768_X25519, KeyTime,
                bcpgKey);
            Assert.That(ReadKeyPacket(v5.GetEncoded()).Key, Is.InstanceOf<UnknownBcpgKey>());

            // v6 key whose explicit key material length disagrees with the algorithm
            byte[] v6 = new PublicKeyPacket(PublicKeyPacket.Version6, PublicKeyAlgorithmTag.MLKem768_X25519, KeyTime,
                bcpgKey).GetEncoded(PacketFormat.Current);
            int lengthPos = Array.IndexOf(v6, (byte)PublicKeyAlgorithmTag.MLKem768_X25519, 3) + 1;
            v6[lengthPos + 3] ^= 0x01;
            Assert.Throws<MalformedPacketException>(() => ReadKeyPacket(v6));
        }
    }
}
