using System;
using System.IO;
using System.Linq;
using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    /// <summary>Tests for the composite ML-DSA+EdDSA signatures, algorithms 30 and 31 of RFC 9980.</summary>
    [TestFixture]
    public class PgpMLDsaEdDsaTest
    {
        private static readonly SecureRandom Random = new SecureRandom();

        private static readonly byte[] Data = Strings.ToUtf8ByteArray("a message to be signed with ML-DSA+EdDSA");

        private static readonly PublicKeyAlgorithmTag[] Algorithms =
        {
            PublicKeyAlgorithmTag.MLDsa65_Ed25519, PublicKeyAlgorithmTag.MLDsa87_Ed448,
        };

        internal static PgpKeyPair NewKeyPair(PublicKeyAlgorithmTag algorithm, int version = 6)
        {
            if (algorithm == PublicKeyAlgorithmTag.MLDsa65_Ed25519)
            {
                var privateKey = new MLDsa65Ed25519PrivateKeyParameters(Random);
                return new PgpKeyPair(version, algorithm, privateKey.GeneratePublicKey(), privateKey, DateTime.UtcNow);
            }
            else
            {
                var privateKey = new MLDsa87Ed448PrivateKeyParameters(Random);
                return new PgpKeyPair(version, algorithm, privateKey.GeneratePublicKey(), privateKey, DateTime.UtcNow);
            }
        }

        /// <summary>
        /// ML-DSA signing is hedged (RFC 9980 5.1.2): two signatures over the same digest share the deterministic
        /// EdDSA part but not the ML-DSA part, and both verify.
        /// </summary>
        [Test]
        public void MLDsaSigningIsHedged()
        {
            foreach (PublicKeyAlgorithmTag algorithm in Algorithms)
            {
                PgpKeyPair pair = NewKeyPair(algorithm);
                int edLength = algorithm == PublicKeyAlgorithmTag.MLDsa65_Ed25519 ? 64 : 114;
                byte[] digest = SecureRandom.GetNextBytes(Random, 64);

                byte[][] signatures = new byte[2][];
                for (int i = 0; i < signatures.Length; ++i)
                {
                    var signer = new PgpCompositeSigner(algorithm);
                    signer.Init(true, pair.PrivateKey.Key);
                    signer.BlockUpdate(digest, 0, digest.Length);
                    signatures[i] = signer.GenerateSignature();
                }

                Assert.That(Arrays.CopyOfRange(signatures[0], 0, edLength),
                    Is.EqualTo(Arrays.CopyOfRange(signatures[1], 0, edLength)), algorithm + " EdDSA part");
                Assert.That(Arrays.CopyOfRange(signatures[0], edLength, signatures[0].Length),
                    Is.Not.EqualTo(Arrays.CopyOfRange(signatures[1], edLength, signatures[1].Length)),
                    algorithm + " ML-DSA part");

                foreach (byte[] signature in signatures)
                {
                    var verifier = new PgpCompositeSigner(algorithm);
                    verifier.Init(false, pair.PublicKey.GetKey());
                    verifier.BlockUpdate(digest, 0, digest.Length);
                    Assert.That(verifier.VerifySignature(signature), Is.True, algorithm.ToString());
                }
            }
        }

        private static int SignatureLength(PublicKeyAlgorithmTag algorithm) =>
            algorithm == PublicKeyAlgorithmTag.MLDsa65_Ed25519 ? 64 + 3309 : 114 + 4627;

        private static PgpSignature Sign(PgpKeyPair pair, HashAlgorithmTag hash, byte[] data)
        {
            var generator = new PgpSignatureGenerator(pair.PublicKey.Algorithm, hash);
            generator.InitSign(PgpSignature.BinaryDocument, pair.PrivateKey);
            generator.Update(data);
            return generator.Generate();
        }

        private static bool Verify(PgpSignature signature, PgpPublicKey key, byte[] data)
        {
            signature.InitVerify(key);
            signature.Update(data);
            return signature.Verify();
        }

        private static PgpSignature Reparse(PgpSignature signature) =>
            ((PgpSignatureList)new PgpObjectFactory(signature.GetEncoded()).NextPgpObject())[0];

        [Test]
        public void SignAndVerify()
        {
            foreach (var algorithm in Algorithms)
            {
                PgpKeyPair pair = NewKeyPair(algorithm);
                Assert.That(pair.PublicKey.Version, Is.EqualTo(6));
                Assert.That(pair.PublicKey.IsEncryptionKey, Is.False);

                foreach (var hash in new[]
                {
                    HashAlgorithmTag.Sha256, HashAlgorithmTag.Sha384, HashAlgorithmTag.Sha512,
                    HashAlgorithmTag.Sha3_256, HashAlgorithmTag.Sha3_512,
                })
                {
                    PgpSignature signature = Sign(pair, hash, Data);
                    Assert.That(signature.Version, Is.EqualTo(6));
                    Assert.That(signature.KeyAlgorithm, Is.EqualTo(algorithm));
                    Assert.That(signature.GetSignature().Length, Is.EqualTo(SignatureLength(algorithm)));
                    Assert.That(signature.GetSalt().Length, Is.EqualTo(PgpUtilities.GetV6SaltSize(hash)));

                    PgpSignature parsed = Reparse(signature);
                    Assert.That(Verify(parsed, pair.PublicKey, Data), Is.True, algorithm + " " + hash);
                    Assert.That(Verify(parsed, pair.PublicKey, Strings.ToUtf8ByteArray("other")), Is.False);
                    Assert.That(Verify(parsed, NewKeyPair(algorithm).PublicKey, Data), Is.False);
                }
            }
        }

        [Test]
        public void EachComponentIsChecked()
        {
            foreach (var algorithm in Algorithms)
            {
                PgpKeyPair pair = NewKeyPair(algorithm);
                PgpSignature signature = Sign(pair, HashAlgorithmTag.Sha512, Data);
                byte[] encoded = signature.GetEncoded();

                byte[] raw = signature.GetSignature();
                int edLength = algorithm == PublicKeyAlgorithmTag.MLDsa65_Ed25519 ? 64 : 114;
                int pos = IndexOf(encoded, Arrays.CopyOfRange(raw, 0, 32));
                Assert.That(pos, Is.GreaterThan(0));

                foreach (int offset in new[]{ 3, edLength - 1, edLength + 5, raw.Length - 1 })
                {
                    byte[] modified = Arrays.Clone(encoded);
                    modified[pos + offset] ^= 0x01;

                    PgpSignature parsed = ((PgpSignatureList)new PgpObjectFactory(modified).NextPgpObject())[0];
                    Assert.That(Verify(parsed, pair.PublicKey, Data), Is.False, algorithm + " offset " + offset);
                }
            }
        }

        private static PgpSignature CopyWithValue(PgpSignature template, PublicKeyAlgorithmTag algorithm,
            byte[] value)
        {
            return new PgpSignature(new SignaturePacket(6, true, template.SignatureType, template.KeyId, algorithm,
                template.HashAlgorithm, template.GetHashedSubPackets().ToSubpacketArray(),
                template.GetUnhashedSubPackets().ToSubpacketArray(), template.GetDigestPrefix(), template.GetSalt(),
                null, value));
        }

        // RFC 9980 9.1: the components of two signatures over the same data cannot be recombined, since every
        // version 6 signature has a salt of its own
        [Test]
        public void ComponentsOfTwoSignaturesCannotBeCombined()
        {
            foreach (var algorithm in Algorithms)
            {
                PgpKeyPair pair = NewKeyPair(algorithm);
                int edLength = algorithm == PublicKeyAlgorithmTag.MLDsa65_Ed25519 ? 64 : 114;

                // the same hashed subpackets, so that the two signatures differ in nothing but their salts
                var hashed = new PgpSignatureSubpacketGenerator();
                hashed.SetSignatureCreationTime(false, DateTime.UtcNow);
                hashed.SetIssuerFingerprint(false, pair.PublicKey);

                var signatures = new PgpSignature[2];
                for (int i = 0; i < signatures.Length; ++i)
                {
                    var generator = new PgpSignatureGenerator(algorithm, HashAlgorithmTag.Sha512);
                    generator.InitSign(PgpSignature.BinaryDocument, pair.PrivateKey);
                    generator.SetHashedSubpackets(hashed.Generate());
                    generator.Update(Data);
                    signatures[i] = generator.Generate();
                    Assert.That(Verify(Reparse(signatures[i]), pair.PublicKey, Data), Is.True);
                }
                Assert.That(signatures[0].GetSalt(), Is.Not.EqualTo(signatures[1].GetSalt()));

                byte[] a = signatures[0].GetSignature(), b = signatures[1].GetSignature();
                byte[] edAMlDsaB = Arrays.Concatenate(Arrays.CopyOfRange(a, 0, edLength),
                    Arrays.CopyOfRange(b, edLength, b.Length));
                byte[] edBMlDsaA = Arrays.Concatenate(Arrays.CopyOfRange(b, 0, edLength),
                    Arrays.CopyOfRange(a, edLength, a.Length));

                foreach (PgpSignature template in signatures)
                {
                    foreach (byte[] value in new[]{ edAMlDsaB, edBMlDsaA })
                    {
                        Assert.That(Verify(CopyWithValue(template, algorithm, value), pair.PublicKey, Data), Is.False,
                            algorithm.ToString());
                    }
                }
            }
        }

        // RFC 9980 9.1: the EdDSA component is a valid EdDSA signature of the digest, but not an OpenPGP signature of
        // the data made by the EdDSA key on its own, since the digest covers the algorithm of the signature
        [Test]
        public void EdDsaComponentIsNotAnEdDsaSignature()
        {
            foreach (var algorithm in Algorithms)
            {
                PgpKeyPair pair = NewKeyPair(algorithm);
                PgpSignature signature = Sign(pair, HashAlgorithmTag.Sha512, Data);

                bool isEd25519 = algorithm == PublicKeyAlgorithmTag.MLDsa65_Ed25519;
                byte[] edSignature = Arrays.CopyOfRange(signature.GetSignature(), 0, isEd25519 ? 64 : 114);
                AsymmetricKeyParameter edKey = isEd25519
                    ? (AsymmetricKeyParameter)((MLDsa65Ed25519PublicKeyParameters)pair.PublicKey.GetKey()).Ed25519Key
                    : ((MLDsa87Ed448PublicKeyParameters)pair.PublicKey.GetKey()).Ed448Key;
                PublicKeyAlgorithmTag edAlgorithm = isEd25519
                    ? PublicKeyAlgorithmTag.Ed25519
                    : PublicKeyAlgorithmTag.Ed448;

                IDigest digest = PgpUtilities.CreateDigest(HashAlgorithmTag.Sha512);
                byte[] salt = signature.GetSalt(), trailer = signature.GetSignatureTrailer();
                digest.BlockUpdate(salt, 0, salt.Length);
                digest.BlockUpdate(Data, 0, Data.Length);
                digest.BlockUpdate(trailer, 0, trailer.Length);
                byte[] hashValue = DigestUtilities.DoFinal(digest);

                ISigner edVerifier = isEd25519 ? (ISigner)new Ed25519Signer() : new Ed448Signer(Arrays.EmptyBytes);
                edVerifier.Init(false, edKey);
                edVerifier.BlockUpdate(hashValue, 0, hashValue.Length);
                Assert.That(edVerifier.VerifySignature(edSignature), Is.True, algorithm.ToString());

                var edPublicKey = new PgpPublicKey(6, edAlgorithm, edKey, pair.PublicKey.CreationTime);
                Assert.That(Verify(CopyWithValue(signature, edAlgorithm, edSignature), edPublicKey, Data), Is.False,
                    algorithm.ToString());
            }
        }

        [Test]
        public void WrongLengthSignaturesAreRejected()
        {
            foreach (var algorithm in Algorithms)
            {
                PgpKeyPair pair = NewKeyPair(algorithm);
                var signer = new PgpCompositeSigner(algorithm);
                signer.Init(true, pair.PrivateKey.Key);
                signer.BlockUpdate(Data, 0, Data.Length);
                byte[] raw = signer.GenerateSignature();
                Assert.That(raw.Length, Is.EqualTo(SignatureLength(algorithm)));

                foreach (byte[] bad in new[]
                {
                    new byte[0], Arrays.CopyOf(raw, raw.Length - 1), Arrays.Append(raw, 0), Arrays.CopyOf(raw, 64),
                })
                {
                    signer.Init(false, pair.PublicKey.GetKey());
                    signer.BlockUpdate(Data, 0, Data.Length);
                    Assert.That(signer.VerifySignature(bad), Is.False);
                }

                signer.Init(false, pair.PublicKey.GetKey());
                signer.BlockUpdate(Data, 0, Data.Length);
                Assert.That(signer.VerifySignature(raw), Is.True);
            }
        }

        [Test]
        public void OnlyVersion6KeysAndMatchingTypes()
        {
            var key65 = new MLDsa65Ed25519PrivateKeyParameters(Random);
            var key87 = new MLDsa87Ed448PrivateKeyParameters(Random);

            Assert.Throws<ArgumentException>(() => NewKeyPair(PublicKeyAlgorithmTag.MLDsa65_Ed25519, 4));
            Assert.Throws<ArgumentException>(() => NewKeyPair(PublicKeyAlgorithmTag.MLDsa87_Ed448, 4));
            Assert.Throws<ArgumentException>(() => new PgpPublicKey(6, PublicKeyAlgorithmTag.MLDsa87_Ed448,
                key65.GeneratePublicKey(), DateTime.UtcNow));
            Assert.Throws<ArgumentException>(() => new PgpPublicKey(6, PublicKeyAlgorithmTag.MLDsa65_Ed25519,
                key87.GeneratePublicKey(), DateTime.UtcNow));
            Assert.Throws<ArgumentException>(() => new PgpPublicKey(6, PublicKeyAlgorithmTag.Ed25519,
                key65.GeneratePublicKey(), DateTime.UtcNow));
            Assert.Throws<ArgumentException>(() => new PgpPublicKey(6, PublicKeyAlgorithmTag.MLDsa65_Ed25519,
                key65.Ed25519Key.GeneratePublicKey(), DateTime.UtcNow));
        }

        [Test]
        public void KeyRingRoundTrip()
        {
            foreach (var algorithm in Algorithms)
            {
                PgpKeyPair pair = NewKeyPair(algorithm);
                var hashed = new PgpSignatureSubpacketGenerator();
                hashed.SetKeyFlags(false, PgpKeyFlags.CanCertify | PgpKeyFlags.CanSign);
                var krg = new PgpKeyRingGenerator(PgpSignature.PositiveCertification, pair, "pq@example.org",
                    SymmetricKeyAlgorithmTag.Null, HashAlgorithmTag.Sha512, new char[0], true, hashed.Generate(), null,
                    Random);

                var secretRing = new PgpSecretKeyRing(krg.GenerateSecretKeyRing().GetEncoded());
                var publicRing = new PgpPublicKeyRing(krg.GeneratePublicKeyRing().GetEncoded());

                PgpSecretKey secretKey = secretRing.GetSecretKey();
                Assert.That(secretKey.IsSigningKey, Is.True);
                PgpPrivateKey privateKey = secretKey.ExtractPrivateKey(new char[0]);

                var generator = new PgpSignatureGenerator(algorithm, HashAlgorithmTag.Sha512);
                generator.InitSign(PgpSignature.BinaryDocument, privateKey);
                generator.Update(Data);
                PgpSignature signature = Reparse(generator.Generate());

                Assert.That(Verify(signature, publicRing.GetPublicKey(), Data), Is.True);
                Assert.That(publicRing.GetPublicKey().GetFingerprint(), Is.EqualTo(pair.PublicKey.GetFingerprint()));

                // the self-certification made by the ring generator verifies with the composite key
                PgpSignature certification = publicRing.GetPublicKey().GetSignaturesForId("pq@example.org")
                    .Cast<PgpSignature>().First();
                certification.InitVerify(publicRing.GetPublicKey());
                Assert.That(certification.VerifyCertification("pq@example.org", publicRing.GetPublicKey()), Is.True);
            }
        }

        [Test]
        public void CorruptedSecretRejected()
        {
            foreach (var algorithm in Algorithms)
            {
                PgpKeyPair pair = NewKeyPair(algorithm);
                var hashed = new PgpSignatureSubpacketGenerator();
                hashed.SetKeyFlags(false, PgpKeyFlags.CanCertify | PgpKeyFlags.CanSign);
                var krg = new PgpKeyRingGenerator(PgpSignature.PositiveCertification, pair, "pq",
                    SymmetricKeyAlgorithmTag.Null, HashAlgorithmTag.Sha512, new char[0], true, hashed.Generate(), null,
                    Random);
                byte[] encoded = krg.GenerateSecretKeyRing().GetEncoded();

                byte[] material = pair.PublicKey.PublicKeyPacket.Key is MLDsa65Ed25519PublicBcpgKey k65
                    ? k65.GetKey()
                    : ((MLDsa87Ed448PublicBcpgKey)pair.PublicKey.PublicKeyPacket.Key).GetKey();
                int pos = IndexOf(encoded, material);
                Assert.That(pos, Is.GreaterThan(0));

                int edLength = algorithm == PublicKeyAlgorithmTag.MLDsa65_Ed25519 ? 32 : 57;

                // unprotected v6 secret key: public material | usage (1) | EdDSA secret | ML-DSA seed (32)
                foreach (int offset in new[]{ 1 + 3, 1 + edLength + 3 })
                {
                    byte[] modified = Arrays.Clone(encoded);
                    modified[pos + material.Length + offset] ^= 0x01;
                    Assert.Throws<PgpException>(() =>
                        new PgpSecretKeyRing(modified).GetSecretKey().ExtractPrivateKey(new char[0]));
                }
            }
        }

        [Test]
        public void OnePassSignature()
        {
            foreach (var algorithm in Algorithms)
            {
                PgpKeyPair pair = NewKeyPair(algorithm);
                var generator = new PgpSignatureGenerator(algorithm, HashAlgorithmTag.Sha512);
                generator.InitSign(PgpSignature.BinaryDocument, pair.PrivateKey);

                var bOut = new MemoryStream();
                generator.GenerateOnePassVersion(false).Encode(bOut);
                using (Stream lit = new PgpLiteralDataGenerator().Open(bOut, PgpLiteralData.Binary, "",
                    Data.Length, DateTime.UtcNow))
                {
                    lit.Write(Data, 0, Data.Length);
                }
                generator.Update(Data);
                generator.Generate().Encode(bOut);

                var factory = new PgpObjectFactory(bOut.ToArray());
                var onePass = ((PgpOnePassSignatureList)factory.NextPgpObject())[0];
                Assert.That(onePass.Version, Is.EqualTo(6));
                Assert.That(onePass.KeyAlgorithm, Is.EqualTo(algorithm));
                onePass.InitVerify(pair.PublicKey);

                var literal = (PgpLiteralData)factory.NextPgpObject();
                byte[] read = Streams.ReadAll(literal.GetInputStream());
                onePass.Update(read);

                var signatures = (PgpSignatureList)factory.NextPgpObject();
                Assert.That(onePass.Verify(signatures[0]), Is.True);
            }
        }

        // The signatures of RFC 9980 for ML-DSA+EdDSA keys verify.
        [Test]
        public void Rfc9980SignaturesVerify()
        {
            int verified = 0;
            foreach (string n in new[]{ "a3", "a4", "a5", "a6", "a7" })
            {
                var publicRing = new PgpPublicKeyRing(PgpV6TestUtilities.LoadRfc9980(n + "-public-key.asc"));
                PgpPublicKey primary = publicRing.GetPublicKey();
                if (primary.Algorithm != PublicKeyAlgorithmTag.MLDsa65_Ed25519 &&
                    primary.Algorithm != PublicKeyAlgorithmTag.MLDsa87_Ed448)
                    continue;

                var secretRing = new PgpSecretKeyRing(PgpV6TestUtilities.LoadRfc9980(n + "-secret-key.asc"));
                var derivedKey = secretRing.GetSecretKey().ExtractPrivateKey(new char[0]);
                Assert.That(derivedKey.Key, Is.Not.Null);

                var signatures = (PgpSignatureList)new PgpObjectFactory(
                    PgpV6TestUtilities.LoadRfc9980(n + "-signature.asc")).NextPgpObject();
                PgpSignature signature = signatures[0];
                Assert.That(signature.KeyAlgorithm, Is.EqualTo(primary.Algorithm), n);
                Assert.That(Verify(signature, primary, PgpV6TestUtilities.Rfc9980Message), Is.True, n);
                ++verified;
            }

            Assert.That(verified, Is.GreaterThan(0));
        }

        private static int IndexOf(byte[] data, byte[] pattern)
        {
            for (int i = 0; i + pattern.Length <= data.Length; ++i)
            {
                if (Arrays.AreEqual(Arrays.CopyOfRange(data, i, i + pattern.Length), pattern))
                    return i;
            }
            return -1;
        }
    }
}
