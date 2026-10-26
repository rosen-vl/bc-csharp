using System;
using System.Linq;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    /// <summary>Tests for SLH-DSA, algorithms 32 to 34 of RFC 9980.</summary>
    [TestFixture]
    public class PgpSlhDsaTest
    {
        private static readonly SecureRandom Random = new SecureRandom();

        private static readonly byte[] Data = Strings.ToUtf8ByteArray("a message to be signed with SLH-DSA");

        private static readonly PublicKeyAlgorithmTag[] Algorithms =
        {
            PublicKeyAlgorithmTag.SlhDsa_Shake128s, PublicKeyAlgorithmTag.SlhDsa_Shake128f,
            PublicKeyAlgorithmTag.SlhDsa_Shake256s,
        };

        private static int SignatureLength(PublicKeyAlgorithmTag algorithm)
        {
            switch (algorithm)
            {
            case PublicKeyAlgorithmTag.SlhDsa_Shake128s: return 7856;
            case PublicKeyAlgorithmTag.SlhDsa_Shake128f: return 17088;
            default: return 29792;
            }
        }

        internal static AsymmetricCipherKeyPair Generate(PublicKeyAlgorithmTag algorithm)
        {
            var generator = new SlhDsaKeyPairGenerator();
            generator.Init(new SlhDsaKeyGenerationParameters(Random, PgpUtilities.GetSlhDsaParameters(algorithm)));
            return generator.GenerateKeyPair();
        }

        internal static PgpKeyPair NewKeyPair(PublicKeyAlgorithmTag algorithm, int version = 6)
        {
            AsymmetricCipherKeyPair pair = Generate(algorithm);
            return new PgpKeyPair(version, algorithm, pair.Public, pair.Private, DateTime.UtcNow);
        }

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
                Assert.That(pair.PublicKey.GetFingerprint().Length, Is.EqualTo(32));

                PgpSignature signature = Sign(pair, HashAlgorithmTag.Sha512, Data);
                Assert.That(signature.Version, Is.EqualTo(6));
                Assert.That(signature.KeyAlgorithm, Is.EqualTo(algorithm));
                Assert.That(signature.GetSignature().Length, Is.EqualTo(SignatureLength(algorithm)), "" + algorithm);

                PgpSignature parsed = Reparse(signature);
                Assert.That(Verify(parsed, pair.PublicKey, Data), Is.True, algorithm.ToString());
                Assert.That(Verify(parsed, pair.PublicKey, Strings.ToUtf8ByteArray("other")), Is.False);
            }
        }

        // RFC 9980 6.1.2 and 9.3: SLH-DSA signing is hedged, so two signatures over the same digest differ
        [Test]
        public void SlhDsaSigningIsHedged()
        {
            PgpKeyPair pair = NewKeyPair(PublicKeyAlgorithmTag.SlhDsa_Shake128f);

            byte[][] signatures = new byte[2][];
            for (int i = 0; i < signatures.Length; ++i)
            {
                ISigner signer = PgpUtilities.CreateSigner(PublicKeyAlgorithmTag.SlhDsa_Shake128f,
                    HashAlgorithmTag.Sha256, pair.PrivateKey.Key);
                signer.Init(true, pair.PrivateKey.Key);
                signer.BlockUpdate(Data, 0, Data.Length);
                signatures[i] = signer.GenerateSignature();
            }
            Assert.That(signatures[0], Is.Not.EqualTo(signatures[1]));

            foreach (byte[] signature in signatures)
            {
                ISigner verifier = PgpUtilities.CreateSigner(PublicKeyAlgorithmTag.SlhDsa_Shake128f,
                    HashAlgorithmTag.Sha256, pair.PublicKey.GetKey());
                verifier.Init(false, pair.PublicKey.GetKey());
                verifier.BlockUpdate(Data, 0, Data.Length);
                Assert.That(verifier.VerifySignature(signature), Is.True);
            }
        }

        [Test]
        public void SeveralHashAlgorithms()
        {
            PgpKeyPair pair = NewKeyPair(PublicKeyAlgorithmTag.SlhDsa_Shake128f);
            foreach (var hash in new[]
            {
                HashAlgorithmTag.Sha256, HashAlgorithmTag.Sha384, HashAlgorithmTag.Sha3_256, HashAlgorithmTag.Sha3_512,
            })
            {
                PgpSignature signature = Reparse(Sign(pair, hash, Data));
                Assert.That(Verify(signature, pair.PublicKey, Data), Is.True, hash.ToString());
            }
        }

        [Test]
        public void TamperedSignatureIsRejected()
        {
            PgpKeyPair pair = NewKeyPair(PublicKeyAlgorithmTag.SlhDsa_Shake128f);
            byte[] encoded = Sign(pair, HashAlgorithmTag.Sha512, Data).GetEncoded();
            byte[] raw = Reparse(Sign(pair, HashAlgorithmTag.Sha512, Data)).GetSignature();

            PgpSignature good = ((PgpSignatureList)new PgpObjectFactory(encoded).NextPgpObject())[0];
            byte[] goodRaw = good.GetSignature();
            int pos = IndexOf(encoded, Arrays.CopyOfRange(goodRaw, 0, 32));
            Assert.That(pos, Is.GreaterThan(0));
            Assert.That(raw.Length, Is.EqualTo(goodRaw.Length));

            foreach (int offset in new[]{ 0, 16, goodRaw.Length / 2, goodRaw.Length - 1 })
            {
                byte[] modified = Arrays.Clone(encoded);
                modified[pos + offset] ^= 0x01;
                PgpSignature parsed = ((PgpSignatureList)new PgpObjectFactory(modified).NextPgpObject())[0];
                Assert.That(Verify(parsed, pair.PublicKey, Data), Is.False, "offset " + offset);
            }
        }

        [Test]
        public void OnlyVersion6KeysAndMatchingParameters()
        {
            foreach (var algorithm in Algorithms)
            {
                Assert.Throws<ArgumentException>(() => NewKeyPair(algorithm, 4), algorithm.ToString());
            }

            AsymmetricCipherKeyPair fast = Generate(PublicKeyAlgorithmTag.SlhDsa_Shake128f);
            Assert.Throws<ArgumentException>(() => new PgpPublicKey(6, PublicKeyAlgorithmTag.SlhDsa_Shake128s,
                fast.Public, DateTime.UtcNow));
            Assert.Throws<ArgumentException>(() => new PgpPublicKey(6, PublicKeyAlgorithmTag.SlhDsa_Shake256s,
                fast.Public, DateTime.UtcNow));
            Assert.Throws<ArgumentException>(() => new PgpPublicKey(6, PublicKeyAlgorithmTag.Ed25519,
                fast.Public, DateTime.UtcNow));
            Assert.Throws<ArgumentException>(() => new PgpPublicKey(6, PublicKeyAlgorithmTag.SlhDsa_Shake128f,
                new MLDsa65Ed25519PrivateKeyParameters(Random).GeneratePublicKey(), DateTime.UtcNow));
        }

        [Test]
        public void KeyRingRoundTrip()
        {
            PgpKeyPair pair = NewKeyPair(PublicKeyAlgorithmTag.SlhDsa_Shake128f);
            var hashed = new PgpSignatureSubpacketGenerator();
            hashed.SetKeyFlags(false, PgpKeyFlags.CanCertify | PgpKeyFlags.CanSign);
            var krg = new PgpKeyRingGenerator(PgpSignature.PositiveCertification, pair, "slh@example.org",
                SymmetricKeyAlgorithmTag.Null, HashAlgorithmTag.Sha512, new char[0], true, hashed.Generate(), null,
                Random);

            var secretRing = new PgpSecretKeyRing(krg.GenerateSecretKeyRing().GetEncoded());
            var publicRing = new PgpPublicKeyRing(krg.GeneratePublicKeyRing().GetEncoded());

            PgpSecretKey secretKey = secretRing.GetSecretKey();
            Assert.That(secretKey.IsSigningKey, Is.True);
            PgpPrivateKey privateKey = secretKey.ExtractPrivateKey(new char[0]);

            var generator = new PgpSignatureGenerator(PublicKeyAlgorithmTag.SlhDsa_Shake128f, HashAlgorithmTag.Sha512);
            generator.InitSign(PgpSignature.BinaryDocument, privateKey);
            generator.Update(Data);
            Assert.That(Verify(Reparse(generator.Generate()), publicRing.GetPublicKey(), Data), Is.True);

            PgpSignature certification = publicRing.GetPublicKey().GetSignaturesForId("slh@example.org")
                .Cast<PgpSignature>().First();
            certification.InitVerify(publicRing.GetPublicKey());
            Assert.That(certification.VerifyCertification("slh@example.org", publicRing.GetPublicKey()), Is.True);
        }

        [Test]
        public void MismatchedEmbeddedPublicKeyRejected()
        {
            PgpKeyPair pair = NewKeyPair(PublicKeyAlgorithmTag.SlhDsa_Shake128f);
            var hashed = new PgpSignatureSubpacketGenerator();
            hashed.SetKeyFlags(false, PgpKeyFlags.CanCertify | PgpKeyFlags.CanSign);
            var krg = new PgpKeyRingGenerator(PgpSignature.PositiveCertification, pair, "slh",
                SymmetricKeyAlgorithmTag.Null, HashAlgorithmTag.Sha512, new char[0], true, hashed.Generate(), null,
                Random);
            byte[] encoded = krg.GenerateSecretKeyRing().GetEncoded();

            byte[] material = ((SlhDsaPublicBcpgKey)pair.PublicKey.PublicKeyPacket.Key).GetKey();
            int pos = IndexOf(encoded, material);
            Assert.That(pos, Is.GreaterThan(0));

            // unprotected v6 secret key: public material | usage (1) | SK.seed | SK.prf | PK.seed | PK.root
            byte[] modified = Arrays.Clone(encoded);
            modified[pos + material.Length + 1 + 32 + 3] ^= 0x01;
            Assert.Throws<PgpException>(() => new PgpSecretKeyRing(modified).GetSecretKey()
                .ExtractPrivateKey(new char[0]));

            modified = Arrays.Clone(encoded);
            modified[pos + material.Length + 1 + 48 + 4] ^= 0x01;
            Assert.Throws<PgpException>(() => new PgpSecretKeyRing(modified).GetSecretKey()
                .ExtractPrivateKey(new char[0]));
        }

        // The signatures of RFC 9980 for SLH-DSA keys verify.
        [Test]
        public void Rfc9980SignaturesVerify()
        {
            int verified = 0;
            foreach (string n in new[]{ "a3", "a4", "a5", "a6", "a7" })
            {
                var publicRing = new PgpPublicKeyRing(PgpV6TestUtilities.LoadRfc9980(n + "-public-key.asc"));
                PgpPublicKey primary = publicRing.GetPublicKey();
                if (!PgpUtilities.IsSlhDsaAlgorithm(primary.Algorithm))
                    continue;

                var secretRing = new PgpSecretKeyRing(PgpV6TestUtilities.LoadRfc9980(n + "-secret-key.asc"));
                PgpPrivateKey privateKey = secretRing.GetSecretKey().ExtractPrivateKey(new char[0]);
                Assert.That(((SlhDsaPrivateKeyParameters)privateKey.Key).GetPublicKeyEncoded(),
                    Is.EqualTo(((SlhDsaPublicKeyParameters)primary.GetKey()).GetEncoded()), n);

                var signatures = (PgpSignatureList)new PgpObjectFactory(
                    PgpV6TestUtilities.LoadRfc9980(n + "-signature.asc")).NextPgpObject();
                Assert.That(signatures[0].KeyAlgorithm, Is.EqualTo(primary.Algorithm), n);
                Assert.That(Verify(signatures[0], primary, PgpV6TestUtilities.Rfc9980Message), Is.True, n);
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
