using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Bcpg.Attr;
using Org.BouncyCastle.Bcpg.Sig;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Date;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    /// <summary>
    /// Cross-cutting tests of RFC 9580 conformance for version 6 data that are not part of the fixtures of the
    /// individual features.
    /// </summary>
    [TestFixture]
    public class PgpRfc9580ConformanceTest
    {
        private static readonly SecureRandom Random = new SecureRandom();

        private static readonly byte[] Data = Strings.ToUtf8ByteArray("conformance");

        private static PgpKeyPair EdDsaPair()
        {
            var generator = new Ed25519KeyPairGenerator();
            generator.Init(new Ed25519KeyGenerationParameters(Random));
            return new PgpKeyPair(6, PublicKeyAlgorithmTag.Ed25519, generator.GenerateKeyPair(), DateTime.UtcNow);
        }

        private static PgpKeyPair EdDsaLegacyPair()
        {
            var generator = new Ed25519KeyPairGenerator();
            generator.Init(new Ed25519KeyGenerationParameters(Random));
            return new PgpKeyPair(PublicKeyAlgorithmTag.EdDsa_Legacy, generator.GenerateKeyPair(), DateTime.UtcNow);
        }

        private static PgpKeyPair Ed448Pair(PublicKeyAlgorithmTag algorithm)
        {
            var generator = new Ed448KeyPairGenerator();
            generator.Init(new Ed448KeyGenerationParameters(Random));
            return new PgpKeyPair(algorithm, generator.GenerateKeyPair(), DateTime.UtcNow);
        }

        private static PgpKeyPair EcdsaPair(string curve)
        {
            var generator = new ECKeyPairGenerator("ECDSA");
            generator.Init(new ECKeyGenerationParameters(ECNamedCurveTable.GetOid(curve), Random));
            return new PgpKeyPair(PublicKeyAlgorithmTag.ECDsa, generator.GenerateKeyPair(), DateTime.UtcNow);
        }

        private static PgpKeyPair X25519Pair()
        {
            var generator = new X25519KeyPairGenerator();
            generator.Init(new X25519KeyGenerationParameters(Random));
            return new PgpKeyPair(6, PublicKeyAlgorithmTag.X25519, generator.GenerateKeyPair(), DateTime.UtcNow);
        }

        private static PgpSignatureSubpacketVector Flags(int flags)
        {
            var generator = new PgpSignatureSubpacketGenerator();
            generator.SetKeyFlags(false, flags);
            return generator.Generate();
        }

        /// <summary>
        /// The S2K of a version 6 SKESK must not use MD5, SHA-1 or RIPEMD-160; with SHA-256 the
        /// message of RFC 9580 A.9 is read.
        /// </summary>
        [Test]
        public void Version6SkeskRefusesWeakS2kHashes()
        {
            byte[] message = PgpV6TestUtilities.LoadRfc9580("a9-eax-message.asc");
            byte[][] packets = PgpUnsupportedVersionTest.SplitPackets(message);
            var original = (SymmetricKeyEncSessionPacket)BcpgInputStream.Wrap(new MemoryStream(packets[0], false))
                .ReadPacket();
            char[] passPhrase = "password".ToCharArray();

            Assert.That(ReadWithPassPhrase(message, passPhrase), Is.Not.Null);

            foreach (var hash in new[]{ HashAlgorithmTag.Sha1, HashAlgorithmTag.MD5, HashAlgorithmTag.RipeMD160 })
            {
                var weak = new S2k(hash, original.S2k.GetIV(), 0xFF);
                var skesk = SymmetricKeyEncSessionPacket.CreateV6Packet(original.EncAlgorithm, original.AeadAlgorithm,
                    original.GetIV(), weak, original.GetSecKeyData(), original.GetAuthTag());

                byte[] modified = Arrays.Concatenate(skesk.GetEncoded(), packets[1]);
                Assert.Catch<PgpException>(() => ReadWithPassPhrase(modified, passPhrase), hash.ToString());
            }
        }

        private static byte[] ReadWithPassPhrase(byte[] message, char[] passPhrase)
        {
            var list = (PgpEncryptedDataList)new PgpObjectFactory(message).NextPgpObject();
            var data = (PgpPbeEncryptedData)list[0];
            using (Stream clear = data.GetDataStream(passPhrase))
            {
                return Streams.ReadAll(clear);
            }
        }

        /// <summary>
        /// An unknown critical subpacket in the hashed area. RFC 9580 5.2.3.7 says an implementation SHOULD
        /// consider the signature in error; the behaviour of this library is recorded here (see the open questions
        /// of the implementation plan).
        /// </summary>
        // RFC 9580 5.2.3.3: EdDSALegacy signatures need a digest of at least 256 bits, and verifiers reject others
        [Test]
        public void EdDsaLegacySignaturesNeedA256BitDigest()
        {
            PgpKeyPair pair = EdDsaLegacyPair();
            CheckMinimumDigest(pair,
                new[]{ HashAlgorithmTag.Sha1, HashAlgorithmTag.RipeMD160, HashAlgorithmTag.Sha224 },
                HashAlgorithmTag.Sha256);
        }

        // RFC 9580 5.2.3.3: over Ed448, which the library also supports for EdDSALegacy, the fsize is 57 octets
        [Test]
        public void EdDsaLegacyOverEd448NeedsA512BitDigest()
        {
            PgpKeyPair pair = Ed448Pair(PublicKeyAlgorithmTag.EdDsa_Legacy);
            foreach (var hash in new[]{ HashAlgorithmTag.Sha256, HashAlgorithmTag.Sha384 })
            {
                var generator = new PgpSignatureGenerator(PublicKeyAlgorithmTag.EdDsa_Legacy, hash);
                Assert.Throws<PgpException>(() => generator.InitSign(PgpSignature.BinaryDocument, pair.PrivateKey),
                    hash.ToString());
            }

            var sha512 = new PgpSignatureGenerator(PublicKeyAlgorithmTag.EdDsa_Legacy, HashAlgorithmTag.Sha512);
            sha512.InitSign(PgpSignature.BinaryDocument, pair.PrivateKey);
            sha512.Update(Data);
            Assert.That(sha512.Generate().HashAlgorithm, Is.EqualTo(HashAlgorithmTag.Sha512));
        }

        private static void CheckMinimumDigest(PgpKeyPair pair, HashAlgorithmTag[] tooSmall,
            HashAlgorithmTag largeEnough)
        {
            foreach (var hash in tooSmall)
            {
                var generator = new PgpSignatureGenerator(PublicKeyAlgorithmTag.EdDsa_Legacy, hash);
                Assert.Throws<PgpException>(() => generator.InitSign(PgpSignature.BinaryDocument, pair.PrivateKey),
                    hash.ToString());

                // even with a valid signature value
                Assert.That(VerifyEdDsaLegacySignature(pair, hash), Is.False, hash.ToString());
            }

            Assert.That(VerifyEdDsaLegacySignature(pair, largeEnough), Is.True);
        }

        // Verify a version 4 EdDSALegacy signature over Data, made with the signer of the library itself so that it
        // can use a hash that the signature generator refuses
        private static bool VerifyEdDsaLegacySignature(PgpKeyPair pair, HashAlgorithmTag hash)
        {
            PgpSignature signature = MakeEdDsaLegacySignature(pair, hash);
            signature.InitVerify(pair.PublicKey);
            signature.Update(Data);
            return signature.Verify();
        }

        // A version 4 signature labelled EdDSALegacy over Data, whatever the algorithm of the (Ed25519 or Ed448) key
        private static PgpSignature MakeEdDsaLegacySignature(PgpKeyPair pair, HashAlgorithmTag hash)
        {
            SignatureSubpacket[] hashed = { new SignatureCreationTime(false, DateTime.UtcNow) };
            var unhashed = new SignatureSubpacket[0];
            byte[] trailer = new SignaturePacket(PgpSignature.BinaryDocument, pair.KeyId,
                PublicKeyAlgorithmTag.EdDsa_Legacy, hash, hashed, unhashed, new byte[2], new MPInteger[0])
                .GetSignatureTrailer();

            IDigest digest = PgpUtilities.CreateDigest(hash);
            digest.BlockUpdate(Data, 0, Data.Length);
            digest.BlockUpdate(trailer, 0, trailer.Length);
            byte[] hashValue = DigestUtilities.DoFinal(digest);

            ISigner signer = PgpUtilities.CreateSigner(PublicKeyAlgorithmTag.EdDsa_Legacy, hash, pair.PrivateKey.Key);
            signer.Init(true, pair.PrivateKey.Key);
            signer.BlockUpdate(Data, 0, Data.Length);
            signer.BlockUpdate(trailer, 0, trailer.Length);
            byte[] value = signer.GenerateSignature();
            // as the signature generator encodes them
            MPInteger[] mpis = value.Length == 64
                ? new[]{ new MPInteger(new BigInteger(1, value, 0, 32)),
                    new MPInteger(new BigInteger(1, value, 32, 32)) }
                : new[]{ new MPInteger(new BigInteger(1, Arrays.Prepend(value, 0x40))),
                    new MPInteger(BigInteger.Zero) };

            return new PgpSignature(new SignaturePacket(PgpSignature.BinaryDocument, pair.KeyId,
                PublicKeyAlgorithmTag.EdDsa_Legacy, hash, hashed, unhashed,
                new byte[]{ hashValue[0], hashValue[1] }, mpis));
        }

        // RFC 9580 5.2.3.10: the expiry of a primary key comes from its newest self-signature that verifies; a
        // forged newer one, here without any expiry, changes nothing
        [TestCase(6)]
        [TestCase(4)]
        public void ForgedSelfSignaturesDoNotChangeTheExpiry(int version)
        {
            var ed25519 = new Ed25519KeyPairGenerator();
            ed25519.Init(new Ed25519KeyGenerationParameters(Random));
            var pair = new PgpKeyPair(version, PublicKeyAlgorithmTag.Ed25519, ed25519.GenerateKeyPair(),
                DateTime.UtcNow.AddHours(-1));
            int type = version == 6 ? PgpSignature.DirectKey : PgpSignature.PositiveCertification;

            PgpPublicKey Add(PgpPublicKey certified, PgpSignature signature) => version == 6
                ? PgpPublicKey.AddCertification(certified, signature)
                : PgpPublicKey.AddCertification(certified, "id", signature);

            PgpSignature SelfSignature(DateTime time, long expiry)
            {
                var hashed = new PgpSignatureSubpacketGenerator();
                hashed.SetSignatureCreationTime(false, time);
                if (expiry > 0)
                {
                    hashed.SetKeyExpirationTime(false, expiry);
                }
                var generator = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha256);
                generator.InitSign(type, pair.PrivateKey);
                generator.SetHashedSubpackets(hashed.Generate());
                return version == 6
                    ? generator.GenerateCertification(pair.PublicKey)
                    : generator.GenerateCertification("id", pair.PublicKey);
            }

            PgpPublicKey key = Add(pair.PublicKey, SelfSignature(DateTime.UtcNow.AddMinutes(-30), 3600));

            // the same newer self-signature without an expiry, with a signature value of zeroes
            PgpSignature valid = SelfSignature(DateTime.UtcNow, 0);
            byte[] salt = version == 6 ? valid.GetSalt() : null;
            var forged = new PgpSignature(new SignaturePacket(version, version == 6, type, pair.KeyId,
                PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha256,
                valid.GetHashedSubPackets().ToSubpacketArray(), valid.GetUnhashedSubPackets().ToSubpacketArray(),
                new byte[2], salt, null, new byte[64]));
            PgpPublicKey withForgery = new PgpPublicKeyRing(Add(key, forged).GetEncoded()).GetPublicKey();
            Assert.That(withForgery.GetValidSeconds(withForgery), Is.EqualTo(3600));
            if (version == 6)
            {
                Assert.That(withForgery.GetValidSeconds(), Is.EqualTo(3600));
            }

            // the genuine newer self-signature removes the expiry
            PgpPublicKey renewed = new PgpPublicKeyRing(Add(key, valid).GetEncoded()).GetPublicKey();
            Assert.That(renewed.GetValidSeconds(renewed), Is.EqualTo(0));
            Assert.That(renewed.GetValidSeconds(), Is.EqualTo(0));
        }

        // RFC 9580 5.2.3.10, 5.2.3.18: the newest valid self-signature decides about the expiry; an expired one is not
        // valid, and the certification type does not matter
        [TestCase(6)]
        [TestCase(4)]
        public void ExpiredSelfSignaturesDoNotChangeTheExpiry(int version)
        {
            var ed25519 = new Ed25519KeyPairGenerator();
            ed25519.Init(new Ed25519KeyGenerationParameters(Random));
            var pair = new PgpKeyPair(version, PublicKeyAlgorithmTag.Ed25519, ed25519.GenerateKeyPair(),
                DateTime.UtcNow.AddHours(-1));

            PgpSignature SelfSignature(int signatureType, DateTime time, long keyExpiry, long signatureExpiry)
            {
                var hashed = new PgpSignatureSubpacketGenerator();
                hashed.SetSignatureCreationTime(false, time);
                hashed.SetKeyExpirationTime(false, keyExpiry);
                if (signatureExpiry > 0)
                {
                    hashed.SetSignatureExpirationTime(false, signatureExpiry);
                }
                var generator = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha256);
                generator.InitSign(signatureType, pair.PrivateKey);
                generator.SetHashedSubpackets(hashed.Generate());
                return signatureType == PgpSignature.DirectKey
                    ? generator.GenerateCertification(pair.PublicKey)
                    : generator.GenerateCertification("id", pair.PublicKey);
            }

            PgpPublicKey Add(PgpPublicKey certified, PgpSignature signature) =>
                new PgpPublicKeyRing((signature.SignatureType == PgpSignature.DirectKey
                    ? PgpPublicKey.AddCertification(certified, signature)
                    : PgpPublicKey.AddCertification(certified, "id", signature)).GetEncoded()).GetPublicKey();

            int type = version == 6 ? PgpSignature.DirectKey : PgpSignature.PositiveCertification;
            PgpPublicKey key = Add(pair.PublicKey, SelfSignature(type, DateTime.UtcNow.AddMinutes(-30), 3600, 0));
            Assert.That(key.GetValidSeconds(key), Is.EqualTo(3600));

            // a newer self-signature without an expiry, which expired itself, does not count
            PgpPublicKey withExpired = Add(key, SelfSignature(type, DateTime.UtcNow.AddMinutes(-20), 0, 60));
            Assert.That(withExpired.GetValidSeconds(withExpired), Is.EqualTo(3600));

            // nor does one made in the future
            PgpPublicKey withFuture = Add(key, SelfSignature(type, DateTime.UtcNow.AddHours(1), 0, 0));
            Assert.That(withFuture.GetValidSeconds(withFuture), Is.EqualTo(3600));

            if (version == 4)
            {
                // a newer certification of another type replaces the older one
                PgpPublicKey renewed = Add(key,
                    SelfSignature(PgpSignature.DefaultCertification, DateTime.UtcNow.AddMinutes(-20), 7200, 0));
                Assert.That(renewed.GetValidSeconds(renewed), Is.EqualTo(7200));
            }
        }

        // RFC 9580 5.12: a user attribute has self-signatures like a user ID, and the newest one counts
        [Test]
        public void SelfSignaturesOfUserAttributesCountForTheExpiry()
        {
            var ed25519 = new Ed25519KeyPairGenerator();
            ed25519.Init(new Ed25519KeyGenerationParameters(Random));
            var pair = new PgpKeyPair(4, PublicKeyAlgorithmTag.Ed25519, ed25519.GenerateKeyPair(),
                DateTime.UtcNow.AddHours(-1));
            var attributesGenerator = new PgpUserAttributeSubpacketVectorGenerator();
            attributesGenerator.SetImageAttribute(ImageAttrib.Format.Jpeg, new byte[]{ 0xFF, 0xD8, 0xFF, 0xD9 });
            PgpUserAttributeSubpacketVector attributes = attributesGenerator.Generate();

            PgpSignatureGenerator Signer(DateTime time, long expiry)
            {
                var hashed = new PgpSignatureSubpacketGenerator();
                hashed.SetSignatureCreationTime(false, time);
                hashed.SetKeyExpirationTime(false, expiry);
                var generator = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha256);
                generator.InitSign(PgpSignature.PositiveCertification, pair.PrivateKey);
                generator.SetHashedSubpackets(hashed.Generate());
                return generator;
            }

            PgpPublicKey key = PgpPublicKey.AddCertification(pair.PublicKey, "id",
                Signer(DateTime.UtcNow.AddMinutes(-30), 0).GenerateCertification("id", pair.PublicKey));
            key = PgpPublicKey.AddCertification(key, attributes,
                Signer(DateTime.UtcNow.AddMinutes(-20), 7200).GenerateCertification(attributes, pair.PublicKey));
            key = new PgpPublicKeyRing(key.GetEncoded()).GetPublicKey();

            Assert.That(key.GetValidSeconds(key), Is.EqualTo(7200));
        }

        // RFC 9580 5.2.3.20: a non-revocable self-signature ignores later revocations
        [TestCase(false)]
        [TestCase(true)]
        public void NonRevocableSelfSignaturesIgnoreRevocations(bool revocable)
        {
            var ed25519 = new Ed25519KeyPairGenerator();
            ed25519.Init(new Ed25519KeyGenerationParameters(Random));
            var pair = new PgpKeyPair(4, PublicKeyAlgorithmTag.Ed25519, ed25519.GenerateKeyPair(),
                DateTime.UtcNow.AddHours(-1));

            PgpSignature SelfSignature(int type, DateTime time, bool isRevocable = true, long expiry = 7200)
            {
                var hashed = new PgpSignatureSubpacketGenerator();
                hashed.SetSignatureCreationTime(false, time);
                if (type != PgpSignature.CertificationRevocation)
                {
                    hashed.SetKeyExpirationTime(false, expiry);
                    hashed.SetRevocable(false, isRevocable);
                }
                var generator = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha256);
                generator.InitSign(type, pair.PrivateKey);
                generator.SetHashedSubpackets(hashed.Generate());
                return generator.GenerateCertification("id", pair.PublicKey);
            }

            PgpPublicKey key = PgpPublicKey.AddCertification(pair.PublicKey, "id",
                SelfSignature(PgpSignature.PositiveCertification, DateTime.UtcNow.AddMinutes(-30), revocable));
            PgpPublicKey revoked = PgpPublicKey.AddCertification(key, "id",
                SelfSignature(PgpSignature.CertificationRevocation, DateTime.UtcNow.AddMinutes(-20)));
            revoked = new PgpPublicKeyRing(revoked.GetEncoded()).GetPublicKey();

            // a revoked user ID has no self-signature left, and the key no expiry
            Assert.That(revoked.GetValidSeconds(revoked), Is.EqualTo(revocable ? 0 : 7200));

            // a newer revocable certification without an expiry is revoked, and the non-revocable one applies again
            key = PgpPublicKey.AddCertification(key, "id",
                SelfSignature(PgpSignature.PositiveCertification, DateTime.UtcNow.AddMinutes(-25), expiry: 0));
            key = PgpPublicKey.AddCertification(key, "id",
                SelfSignature(PgpSignature.CertificationRevocation, DateTime.UtcNow.AddMinutes(-20)));
            key = new PgpPublicKeyRing(key.GetEncoded()).GetPublicKey();
            Assert.That(key.GetValidSeconds(key), Is.EqualTo(revocable ? 0 : 7200));
        }

        // validating key parameters can be costly (large RSA moduli are tested for primality), and the validity of a
        // certificate takes several self-signatures, so the parameters are made once
        [Test]
        public void KeyParametersAreMadeOnce()
        {
            PgpKeyPair pair = EdDsaPair();
            PgpPublicKey key = pair.PublicKey;
            Assert.That(key.GetKey(), Is.SameAs(key.GetKey()));

            var generator = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha256);
            generator.InitSign(PgpSignature.DirectKey, pair.PrivateKey);
            PgpPublicKey certified = PgpPublicKey.AddCertification(key, generator.GenerateCertification(key));
            Assert.That(certified.GetKey(), Is.SameAs(key.GetKey()));
        }

        // the strings of GetUserIds() are not decoded as UTF-8, so such user IDs are verified in their raw form
        [Test]
        public void SelfSignaturesOfUserIdsWithOtherThanAsciiCharacters()
        {
            var ed25519 = new Ed25519KeyPairGenerator();
            ed25519.Init(new Ed25519KeyGenerationParameters(Random));
            var pair = new PgpKeyPair(4, PublicKeyAlgorithmTag.Ed25519, ed25519.GenerateKeyPair(),
                DateTime.UtcNow.AddHours(-1));
            string id = "Ricarda S. Álvarez";

            var hashed = new PgpSignatureSubpacketGenerator();
            hashed.SetKeyExpirationTime(false, 3600);
            var generator = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha256);
            generator.InitSign(PgpSignature.PositiveCertification, pair.PrivateKey);
            generator.SetHashedSubpackets(hashed.Generate());
            PgpSignature certification = generator.GenerateCertification(id, pair.PublicKey);
            PgpPublicKey key = new PgpPublicKeyRing(
                PgpPublicKey.AddCertification(pair.PublicKey, id, certification).GetEncoded()).GetPublicKey();

            Assert.That(key.GetValidSeconds(key), Is.EqualTo(3600));

            byte[] rawId = key.GetRawUserIds().Single();
            Assert.That(rawId, Is.EqualTo(Strings.ToUtf8ByteArray(id)));
            PgpSignature signature = key.GetSignaturesForId(rawId).Single();
            signature.InitVerify(key);
            Assert.That(signature.VerifyCertification(rawId, key), Is.True);
        }

        // RFC 9580 5.2.3.12, 5.2.3.35: no issuer key ID in version 6 signatures, and an issuer fingerprint names a
        // key of the version of the signature
        [Test]
        public void IssuerMetadataMatchesTheSignatureVersion()
        {
            PgpKeyPair v6 = EdDsaPair();
            foreach (bool inHashed in new[]{ true, false })
            {
                var keyId = new PgpSignatureSubpacketGenerator();
                keyId.SetIssuerKeyID(false, v6.KeyId);
                var generator = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha256);
                generator.InitSign(PgpSignature.BinaryDocument, v6.PrivateKey);
                if (inHashed)
                {
                    generator.SetHashedSubpackets(keyId.Generate());
                }
                else
                {
                    generator.SetUnhashedSubpackets(keyId.Generate());
                }
                generator.Update(Data);
                Assert.Throws<PgpException>(() => generator.Generate(), inHashed ? "hashed" : "unhashed");
            }

            var ed25519 = new Ed25519KeyPairGenerator();
            ed25519.Init(new Ed25519KeyGenerationParameters(Random));
            var v4 = new PgpKeyPair(4, PublicKeyAlgorithmTag.Ed25519, ed25519.GenerateKeyPair(), DateTime.UtcNow);
            foreach (int claimed in new[]{ 6, 4 })
            {
                var fingerprint = new IssuerFingerprint(false, claimed, v4.PublicKey.GetFingerprint());
                var generator = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha256);
                generator.InitSign(PgpSignature.BinaryDocument, v4.PrivateKey);
                generator.SetHashedSubpackets(new PgpSignatureSubpacketVector(new SignatureSubpacket[]{ fingerprint }));
                PgpOnePassSignature onePass = generator.GenerateOnePassVersion(false);
                generator.Update(Data);
                PgpSignature signature = ((PgpSignatureList)new PgpObjectFactory(generator.Generate().GetEncoded())
                    .NextPgpObject())[0];

                signature.InitVerify(v4.PublicKey);
                signature.Update(Data);
                Assert.That(signature.Verify(), Is.EqualTo(claimed == 4), "claimed version " + claimed);

                onePass.InitVerify(v4.PublicKey);
                onePass.Update(Data);
                Assert.That(onePass.Verify(signature), Is.EqualTo(claimed == 4), "claimed version " + claimed);
            }
        }

        // RFC 9580 5.2.3.35: an issuer fingerprint of another version is refused in version 6 signatures, and makes a
        // new version 4 signature invalid at once, as it does once encoded and read again
        [Test]
        public void GeneratedIssuerFingerprintsOfOtherVersions()
        {
            PgpKeyPair v6 = EdDsaPair();
            foreach (bool inHashed in new[]{ true, false })
            {
                var subpackets = new PgpSignatureSubpacketVector(new SignatureSubpacket[]
                {
                    new IssuerFingerprint(false, 4, new byte[20]),
                });
                var generator = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha256);
                generator.InitSign(PgpSignature.BinaryDocument, v6.PrivateKey);
                if (inHashed)
                {
                    generator.SetHashedSubpackets(subpackets);
                }
                else
                {
                    generator.SetUnhashedSubpackets(subpackets);
                }
                generator.Update(Data);
                Assert.Throws<PgpException>(() => generator.Generate(), inHashed ? "hashed" : "unhashed");
            }

            var ed25519 = new Ed25519KeyPairGenerator();
            ed25519.Init(new Ed25519KeyGenerationParameters(Random));
            var v4 = new PgpKeyPair(4, PublicKeyAlgorithmTag.Ed25519, ed25519.GenerateKeyPair(), DateTime.UtcNow);
            var signer = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha256);
            signer.InitSign(PgpSignature.BinaryDocument, v4.PrivateKey);
            signer.SetUnhashedSubpackets(new PgpSignatureSubpacketVector(new SignatureSubpacket[]
            {
                new IssuerFingerprint(false, 6, new byte[32]),
            }));
            signer.Update(Data);
            PgpSignature signature = signer.Generate();
            signature.InitVerify(v4.PublicKey);
            signature.Update(Data);
            Assert.That(signature.Verify(), Is.False);
        }

        // RFC 9580 5.2.3.35: the subpackets that Join brings in count as those of a parsed signature
        [TestCase(4)]
        [TestCase(6)]
        public void JoinedIssuerFingerprintsOfOtherVersions(int version)
        {
            var ed25519 = new Ed25519KeyPairGenerator();
            ed25519.Init(new Ed25519KeyGenerationParameters(Random));
            var pair = new PgpKeyPair(version, PublicKeyAlgorithmTag.Ed25519, ed25519.GenerateKeyPair(),
                DateTime.UtcNow);
            var generator = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha256);
            generator.InitSign(PgpSignature.BinaryDocument, pair.PrivateKey);
            generator.Update(Data);
            PgpSignature signature = ((PgpSignatureList)new PgpObjectFactory(generator.Generate().GetEncoded())
                .NextPgpObject())[0];

            // the same signature with an issuer fingerprint of the other version in its unhashed area
            int otherVersion = version == 6 ? 4 : 6;
            var fingerprint = new IssuerFingerprint(false, otherVersion,
                new byte[otherVersion == 6 ? 32 : 20]);
            SignaturePacket packet = new SignaturePacket(
                PgpV6TestUtilities.ReadPacket<SignaturePacket>(signature.GetEncoded()),
                signature.GetHashedSubPackets().ToSubpacketArray(), new SignatureSubpacket[]{ fingerprint });
            PgpSignature other = ((PgpSignatureList)new PgpObjectFactory(packet.GetEncoded()).NextPgpObject())[0];

            bool Verifies(PgpSignature candidate)
            {
                candidate.InitVerify(pair.PublicKey);
                candidate.Update(Data);
                return candidate.Verify();
            }

            Assert.That(Verifies(PgpSignature.Join(signature, signature)), Is.True);
            PgpSignature joined = PgpSignature.Join(signature, other);
            Assert.That(Verifies(joined), Is.False);
            Assert.That(Verifies(((PgpSignatureList)new PgpObjectFactory(joined.GetEncoded()).NextPgpObject())[0]),
                Is.False);
        }

        // RFC 9580 5.2.3.35: a mismatched issuer fingerprint version makes the signature malformed, in either area
        [Test]
        public void UnhashedIssuerFingerprintOfOtherVersionMakesVersion4SignaturesMalformed()
        {
            var ed25519 = new Ed25519KeyPairGenerator();
            ed25519.Init(new Ed25519KeyGenerationParameters(Random));
            var v4 = new PgpKeyPair(4, PublicKeyAlgorithmTag.Ed25519, ed25519.GenerateKeyPair(), DateTime.UtcNow);

            var fingerprint = new IssuerFingerprint(false, 6, Arrays.CopyOf(v4.PublicKey.GetFingerprint(), 32));
            var generator = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha256);
            generator.InitSign(PgpSignature.BinaryDocument, v4.PrivateKey);
            generator.SetUnhashedSubpackets(new PgpSignatureSubpacketVector(new SignatureSubpacket[]{ fingerprint }));
            PgpOnePassSignature onePass = generator.GenerateOnePassVersion(false);
            generator.Update(Data);
            PgpSignature signature = ((PgpSignatureList)new PgpObjectFactory(generator.Generate().GetEncoded())
                .NextPgpObject())[0];

            signature.InitVerify(v4.PublicKey);
            signature.Update(Data);
            Assert.That(signature.Verify(), Is.False);

            onePass.InitVerify(v4.PublicKey);
            onePass.Update(Data);
            Assert.That(onePass.Verify(signature), Is.False);
        }

        // RFC 9580 5.2.1.16, 5.2.3.2-5, 10.3.2.2: version 3 signatures are only made with RSA and DSA keys of version
        // 3 or 4, and never of the reserved type 0xFF
        [Test]
        public void Version3SignaturesAreRestricted()
        {
            foreach (var algorithm in new[]{ PublicKeyAlgorithmTag.ECDsa, PublicKeyAlgorithmTag.EdDsa_Legacy,
                PublicKeyAlgorithmTag.Ed25519, PublicKeyAlgorithmTag.MLDsa65_Ed25519 })
            {
                Assert.Throws<ArgumentException>(() => new PgpV3SignatureGenerator(algorithm, HashAlgorithmTag.Sha256),
                    algorithm.ToString());
            }

            var rsaGenerator = new RsaKeyPairGenerator();
            rsaGenerator.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(0x10001), Random, 2048, 25));
            AsymmetricCipherKeyPair rsa = rsaGenerator.GenerateKeyPair();
            var v4 = new PgpKeyPair(4, PublicKeyAlgorithmTag.RsaGeneral, rsa, DateTime.UtcNow);
            var v6 = new PgpKeyPair(6, PublicKeyAlgorithmTag.RsaGeneral, rsa, DateTime.UtcNow);

            var generator = new PgpV3SignatureGenerator(PublicKeyAlgorithmTag.RsaGeneral, HashAlgorithmTag.Sha256);
            Assert.Throws<PgpException>(() => generator.InitSign(PgpSignature.BinaryDocument, v6.PrivateKey));
            Assert.Throws<ArgumentException>(() => generator.InitSign(0xFF, v4.PrivateKey));
            Assert.Throws<PgpException>(() => new PgpV3SignatureGenerator(PublicKeyAlgorithmTag.Dsa,
                HashAlgorithmTag.Sha256).InitSign(PgpSignature.BinaryDocument, v4.PrivateKey));

            generator.InitSign(PgpSignature.BinaryDocument, v4.PrivateKey);
            generator.Update(Data);
            PgpSignature signature = generator.Generate();
            Assert.That(signature.Version, Is.EqualTo(3));
            signature.InitVerify(v4.PublicKey);
            signature.Update(Data);
            Assert.That(signature.Verify(), Is.True);
        }

        // A signature is of the algorithm of its key: EdDSALegacy and Ed25519 are distinct algorithms, so a native
        // Ed25519 key makes no EdDSALegacy signature, and neither a signature nor a one-pass signature labelled
        // EdDSALegacy verifies with it
        [Test]
        public void SignatureAlgorithmIsTheKeyAlgorithm()
        {
            var generator = new Ed25519KeyPairGenerator();
            generator.Init(new Ed25519KeyGenerationParameters(Random));
            var native = new PgpKeyPair(4, PublicKeyAlgorithmTag.Ed25519, generator.GenerateKeyPair(), DateTime.UtcNow);
            Assert.Throws<PgpException>(() => new PgpSignatureGenerator(PublicKeyAlgorithmTag.EdDsa_Legacy,
                HashAlgorithmTag.Sha256).InitSign(PgpSignature.BinaryDocument, native.PrivateKey));

            foreach (var (pair, matches) in new[]{ (native, false), (EdDsaLegacyPair(), true) })
            {
                PgpSignature signature = MakeEdDsaLegacySignature(pair, HashAlgorithmTag.Sha256);
                signature.InitVerify(pair.PublicKey);
                signature.Update(Data);
                Assert.That(signature.Verify(), Is.EqualTo(matches));

                var onePass = new PgpOnePassSignature(new OnePassSignaturePacket(PgpSignature.BinaryDocument,
                    HashAlgorithmTag.Sha256, PublicKeyAlgorithmTag.EdDsa_Legacy, pair.KeyId, false));
                onePass.InitVerify(pair.PublicKey);
                onePass.Update(Data);
                Assert.That(onePass.Verify(signature), Is.EqualTo(matches));
            }
        }

        // RFC 9580 5.2.3.3, 5.5.5.6.1.1, 12.5, 12.6: DSA, Elgamal, EdDSALegacy and Curve25519Legacy are not for
        // version 6 keys. Their key material is kept opaque there, so that they cannot be used.
        [Test]
        public void LegacyAlgorithmsAreOpaqueInVersion6Keys()
        {
            var x25519 = new X25519KeyPairGenerator();
            x25519.Init(new X25519KeyGenerationParameters(Random));
            PgpKeyPair curve25519Legacy = new PgpKeyPair(PublicKeyAlgorithmTag.ECDH, x25519.GenerateKeyPair(),
                DateTime.UtcNow);

            var cases = new (PublicKeyAlgorithmTag, BcpgObject)[]
            {
                (PublicKeyAlgorithmTag.Dsa, new DsaPublicBcpgKey(BigInteger.ValueOf(23), BigInteger.ValueOf(11),
                    BigInteger.ValueOf(4), BigInteger.ValueOf(8))),
                (PublicKeyAlgorithmTag.ElGamalEncrypt, new ElGamalPublicBcpgKey(BigInteger.ValueOf(23),
                    BigInteger.ValueOf(5), BigInteger.ValueOf(8))),
                (PublicKeyAlgorithmTag.EdDsa_Legacy, (BcpgObject)EdDsaLegacyPair().PublicKey.PublicKeyPacket.Key),
                (PublicKeyAlgorithmTag.ECDH, (BcpgObject)curve25519Legacy.PublicKey.PublicKeyPacket.Key),
            };
            foreach (var (algorithm, key) in cases)
            {
                byte[] material = key.GetEncoded();

                // the same material is a usable version 4 key
                byte[] v4Body = Arrays.Concatenate(new byte[]{ 4, 0, 0, 0, 1, (byte)algorithm }, material);
                var v4Packet = PgpV6TestUtilities.ReadPacket<PublicKeyPacket>(
                    PgpV6TestUtilities.NewFormatPacket(PacketTag.PublicKey, v4Body));
                Assert.That(v4Packet.Key, Is.Not.InstanceOf<UnknownBcpgKey>(), algorithm.ToString());

                byte[] v6Body = Arrays.ConcatenateAll(new byte[]{ 6, 0, 0, 0, 1, (byte)algorithm },
                    Pack.UInt32_To_BE((uint)material.Length), material);
                byte[] v6Encoding = PgpV6TestUtilities.NewFormatPacket(PacketTag.PublicKey, v6Body);
                var v6Packet = PgpV6TestUtilities.ReadPacket<PublicKeyPacket>(v6Encoding);
                Assert.That(v6Packet.Key, Is.InstanceOf<UnknownBcpgKey>(), algorithm.ToString());

                var v6Key = new PgpPublicKey(v6Packet);
                Assert.That(v6Key.GetEncoded(), Is.EqualTo(v6Encoding), algorithm.ToString());
                Assert.Throws<PgpException>(() => v6Key.GetKey(), algorithm.ToString());
                if (algorithm == PublicKeyAlgorithmTag.ECDH)
                {
                    var generator = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes128, AeadAlgorithmTag.Ocb,
                        Random);
                    Assert.Throws<ArgumentException>(() => generator.AddMethod(v6Key));
                }
            }

            // ECDH over the curves of RFC 9580 9.2 stays usable in version 6 keys
            var ecdh = new ECKeyPairGenerator("ECDH");
            ecdh.Init(new ECKeyGenerationParameters(ECNamedCurveTable.GetOid("P-256"), Random));
            var p256 = new PgpKeyPair(6, PublicKeyAlgorithmTag.ECDH, ecdh.GenerateKeyPair(), DateTime.UtcNow);
            var reparsed = new PgpPublicKey(PgpV6TestUtilities.ReadPacket<PublicKeyPacket>(
                p256.PublicKey.PublicKeyPacket.GetEncoded()));
            Assert.That(reparsed.GetKey(), Is.InstanceOf<ECPublicKeyParameters>());
        }

        // RFC 9580 6.2.2.3, 7.1: the signatures of a cleartext signed message with another armor header than a
        // well-formed Hash header are not validated; the text stays readable
        [TestCase(null, true)]
        [TestCase("SHA256", true)]
        [TestCase("SHA1, SHA512", true)]
        [TestCase("SHA256,SHA3-256", true)]
        [TestCase("SHA256 and some text", false)]
        [TestCase("SHA256, ", false)]
        [TestCase("SHA256;SHA512", false)]
        [TestCase("NOT-A-HASH", false)]
        [TestCase("", false)]
        [TestCase("SHA256\nHash: SHA512", true)]
        [TestCase("SHA256\nComment: injected", false)]
        [TestCase("SHA256\nVersion: 1.0", false)]
        [TestCase("SHA256\nCharset: UTF-8", false)]
        [TestCase("SHA256\nX-Unknown: value", false)]
        public void SignaturesNeedAConformantHashHeader(string hashHeader, bool conformant)
        {
            PgpKeyPair pair = EdDsaPair();
            var generator = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha256);
            generator.InitSign(PgpSignature.CanonicalTextDocument, pair.PrivateKey);
            generator.Update(Data);
            var signatureOut = new MemoryStream();
            using (var armorOut = ArmoredOutputStream.Build().Build(signatureOut))
            {
                generator.Generate().Encode(armorOut);
            }

            string message = "-----BEGIN PGP SIGNED MESSAGE-----\n" +
                (hashHeader == null ? "" : "Hash: " + hashHeader + "\n") + "\n" +
                Strings.FromUtf8ByteArray(Data) + "\n" + Strings.FromUtf8ByteArray(signatureOut.ToArray());

            var armorIn = new ArmoredInputStream(new MemoryStream(Strings.ToUtf8ByteArray(message), false));
            var text = new MemoryStream();
            int c;
            while (armorIn.IsClearText() && (c = armorIn.ReadByte()) >= 0)
            {
                text.WriteByte((byte)c);
            }
            Assert.That(Strings.FromUtf8ByteArray(text.ToArray()), Does.StartWith(Strings.FromUtf8ByteArray(Data)));

            if (conformant)
            {
                var signatures = (PgpSignatureList)new PgpObjectFactory(armorIn).NextPgpObject();
                PgpSignature signature = signatures[0];
                signature.InitVerify(pair.PublicKey);
                signature.Update(Data);
                Assert.That(signature.Verify(), Is.True);
            }
            else
            {
                Assert.Throws<ArmoredInputException>(() => new PgpObjectFactory(armorIn).NextPgpObject());
            }
        }

        // A version 3 PKESK for symmetric algorithm 0 ("plaintext") is refused, rather than its payload being passed
        // on unencrypted and without the integrity check
        [Test]
        public void PlaintextSessionKeysAreRefused()
        {
            var rsaGenerator = new RsaKeyPairGenerator();
            rsaGenerator.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(0x10001), Random, 2048, 25));
            var rsa = new PgpKeyPair(PublicKeyAlgorithmTag.RsaGeneral, rsaGenerator.GenerateKeyPair(), DateTime.UtcNow);

            var generator = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes128, true, Random);
            generator.AddMethod(rsa.PublicKey);
            var bOut = new MemoryStream();
            using (Stream encOut = generator.Open(bOut, Data.Length))
            {
                encOut.Write(Data, 0, Data.Length);
            }
            byte[][] packets = PgpUnsupportedVersionTest.SplitPackets(bOut.ToArray());

            // the message as it is decrypts
            var original = (PgpPublicKeyEncryptedData)((PgpEncryptedDataList)new PgpObjectFactory(bOut.ToArray())
                .NextPgpObject())[0];
            Assert.That(Streams.ReadAll(original.GetDataStream(rsa.PrivateKey)).Length, Is.GreaterThan(0));

            // algorithm 0, a key of zeroes and its checksum, which is zero as well
            var rsaCipher = CipherUtilities.GetCipher("RSA//PKCS1Padding");
            rsaCipher.Init(true, new ParametersWithRandom(rsa.PublicKey.GetKey(), Random));
            byte[] encrypted = rsaCipher.DoFinal(new byte[1 + 16 + 2]);
            byte[] pkesk = PublicKeyEncSessionPacket.CreateV3Packet(rsa.KeyId, PublicKeyAlgorithmTag.RsaGeneral,
                new[]{ new MPInteger(new BigInteger(1, encrypted)).GetEncoded() }).GetEncoded();

            var crafted = (PgpPublicKeyEncryptedData)((PgpEncryptedDataList)new PgpObjectFactory(
                Arrays.Concatenate(pkesk, packets[1])).NextPgpObject())[0];
            Assert.Throws<PgpException>(() => crafted.GetDataStream(rsa.PrivateKey));
        }

        // RFC 9580 9.5: no new signatures or S2Ks with MD5, SHA-1 or RIPEMD-160, but old signatures still verify
        [Test]
        public void WeakHashesAreOnlyRefusedForNewData()
        {
            PgpKeyPair ecdsa = EcdsaPair("P-256");
            var rsaGenerator = new RsaKeyPairGenerator();
            rsaGenerator.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(0x10001), Random, 1024, 25));
            var rsa = new PgpKeyPair(PublicKeyAlgorithmTag.RsaGeneral, rsaGenerator.GenerateKeyPair(), DateTime.UtcNow);

            foreach (var hash in new[]{ HashAlgorithmTag.MD5, HashAlgorithmTag.Sha1, HashAlgorithmTag.RipeMD160 })
            {
                Assert.Throws<PgpException>(() => new PgpSignatureGenerator(PublicKeyAlgorithmTag.ECDsa, hash)
                    .InitSign(PgpSignature.BinaryDocument, ecdsa.PrivateKey), hash.ToString());
                Assert.Throws<PgpException>(() => new PgpV3SignatureGenerator(PublicKeyAlgorithmTag.RsaGeneral, hash)
                    .InitSign(PgpSignature.BinaryDocument, rsa.PrivateKey), hash.ToString());

                var encryptor = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes128, true, Random);
                Assert.Throws<ArgumentException>(() => encryptor.AddMethod("secret".ToCharArray(), hash),
                    hash.ToString());
            }

            // an old SHA-1 binding, made without the checks of the generator, still verifies
            PgpPublicKey subkey = EcdsaPair("P-256").PublicKey;
            PgpSignature old = PgpMLKemX25519Test.SignKeysDirectly(ecdsa, PgpSignature.SubkeyBinding,
                HashAlgorithmTag.Sha1, ecdsa.PublicKey, subkey);
            old.InitVerify(ecdsa.PublicKey);
            Assert.That(old.VerifyCertification(ecdsa.PublicKey, subkey), Is.True);

            // RFC 9580 5.2.5: but a signature with a hash known to be weak, as MD5, is never validated
            Assert.That(VerifyRawRsaSignature(rsa, HashAlgorithmTag.Sha1), Is.True);
            Assert.That(VerifyRawRsaSignature(rsa, HashAlgorithmTag.MD5), Is.False);
            Assert.Throws<PgpException>(() => new PgpSignatureGenerator(PublicKeyAlgorithmTag.RsaGeneral,
                HashAlgorithmTag.MD2).InitSign(PgpSignature.BinaryDocument, rsa.PrivateKey));
        }

        // Verify a version 4 RSA signature over Data made with the signer of the library itself, so that it can use
        // a hash that the signature generator refuses
        private static bool VerifyRawRsaSignature(PgpKeyPair rsa, HashAlgorithmTag hash)
        {
            SignatureSubpacket[] hashed = { new SignatureCreationTime(false, DateTime.UtcNow) };
            var unhashed = new SignatureSubpacket[0];
            byte[] data = Arrays.Concatenate(Data, new SignaturePacket(PgpSignature.BinaryDocument, rsa.KeyId,
                PublicKeyAlgorithmTag.RsaGeneral, hash, hashed, unhashed, new byte[2], new MPInteger[0])
                .GetSignatureTrailer());

            ISigner signer = PgpUtilities.CreateSigner(PublicKeyAlgorithmTag.RsaGeneral, hash, rsa.PrivateKey.Key);
            signer.Init(true, rsa.PrivateKey.Key);
            signer.BlockUpdate(data, 0, data.Length);
            byte[] hashValue = DigestUtilities.DoFinal(PgpUtilities.CreateDigest(hash), data);

            var signature = new PgpSignature(new SignaturePacket(PgpSignature.BinaryDocument, rsa.KeyId,
                PublicKeyAlgorithmTag.RsaGeneral, hash, hashed, unhashed, new byte[]{ hashValue[0], hashValue[1] },
                new[]{ new MPInteger(new BigInteger(1, signer.GenerateSignature())) }));
            signature.InitVerify(rsa.PublicKey);
            signature.Update(Data);
            return signature.Verify();
        }

        // RFC 9580 9.5: the defaults of the legacy constructors certify and bind with SHA-256, not SHA-1
        [Test]
        public void LegacyConstructorsSignWithSha256() =>
            CheckLegacyDefaults(EdDsaLegacyPair(), HashAlgorithmTag.Sha256);

        // RFC 9580 5.2.3.2: ECDSA needs a digest of the fsize of the curve, and 512 bits for P-521
        [TestCase("P-256", HashAlgorithmTag.Sha256)]
        [TestCase("P-384", HashAlgorithmTag.Sha384)]
        [TestCase("P-521", HashAlgorithmTag.Sha512)]
        [TestCase("brainpoolP256r1", HashAlgorithmTag.Sha256)]
        [TestCase("brainpoolP384r1", HashAlgorithmTag.Sha384)]
        [TestCase("brainpoolP512r1", HashAlgorithmTag.Sha512)]
        public void LegacyConstructorsSignWithHashesOfTheCurveSize(string curve, HashAlgorithmTag expected) =>
            CheckLegacyDefaults(EcdsaPair(curve), expected);

        // RFC 9580 5.2.3.5: Ed448 needs 512 bits, so the defaults used to fail for version 4 Ed448 keys
        [Test]
        public void LegacyConstructorsSignWithSha512ForEd448()
        {
            CheckLegacyDefaults(Ed448Pair(PublicKeyAlgorithmTag.Ed448), HashAlgorithmTag.Sha512);

            // EdDSALegacy keys over Ed448 cannot be read back (yet), but get the hash of the curve
            var generator = new PgpKeyRingGenerator(PgpSignature.PositiveCertification,
                Ed448Pair(PublicKeyAlgorithmTag.EdDsa_Legacy), "legacy", SymmetricKeyAlgorithmTag.Null, new char[0],
                true, null, null, Random);
            Assert.That(generator.GeneratePublicKeyRing().GetPublicKey().GetSignaturesForId("legacy").Single()
                .HashAlgorithm, Is.EqualTo(HashAlgorithmTag.Sha512));
        }

        private static void CheckLegacyDefaults(PgpKeyPair primary, HashAlgorithmTag expected)
        {
            var generator = new PgpKeyRingGenerator(PgpSignature.PositiveCertification, primary, "legacy",
                SymmetricKeyAlgorithmTag.Null, new char[0], true, null, null, Random);
            generator.AddSubKey(EdDsaLegacyPair(), null, null);
            PgpPublicKeyRing ring = generator.GeneratePublicKeyRing();

            PgpPublicKey master = ring.GetPublicKey();
            PgpSignature certification = master.GetSignaturesForId("legacy").Single();
            Assert.That(certification.HashAlgorithm, Is.EqualTo(expected));
            certification.InitVerify(master);
            Assert.That(certification.VerifyCertification("legacy", master), Is.True);

            PgpPublicKey subkey = ring.GetPublicKeys().Skip(1).Single();
            PgpSignature binding = subkey.GetSignaturesOfType(PgpSignature.SubkeyBinding).Single();
            Assert.That(binding.HashAlgorithm, Is.EqualTo(expected));
            binding.InitVerify(master);
            Assert.That(binding.VerifyCertification(master, subkey), Is.True);
        }

        // RFC 9580 5.2.3.7, 5.2.5: a signature with an unknown critical hashed subpacket is not validated; for now
        // this only applies to version 6 signatures, and a non-critical one does not matter
        [Test]
        public void UnknownCriticalHashedSubpacketsInvalidateVersion6Signatures()
        {
            foreach (int version in new[]{ 4, 6 })
            foreach (bool isCritical in new[]{ true, false })
            foreach (bool isNotation in new[]{ false, true })
            {
                var generator = new Ed25519KeyPairGenerator();
                generator.Init(new Ed25519KeyGenerationParameters(Random));
                var pair = new PgpKeyPair(version, PublicKeyAlgorithmTag.Ed25519, generator.GenerateKeyPair(),
                    DateTime.UtcNow);

                var signer = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha256);
                signer.InitSign(PgpSignature.BinaryDocument, pair.PrivateKey);

                var subpackets = new PgpSignatureSubpacketGenerator();
                subpackets.SetSignatureCreationTime(false, DateTime.UtcNow);
                signer.SetHashedSubpackets(subpackets.Generate());
                signer.Update(Data);
                PgpSignature plain = signer.Generate();

                // the same signature with an extra, unknown subpacket of type 98, or a notation, of which none is
                // known (RFC 9580 5.2.3.24)
                SignatureSubpacket critical = isNotation
                    ? new NotationData(isCritical, true, "unknown@example.org", "value")
                    : new SignatureSubpacket((SignatureSubpacketTag)98, isCritical, false, new byte[]{ 1, 2, 3 });
                signer = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha256);
                signer.InitSign(PgpSignature.BinaryDocument, pair.PrivateKey);
                signer.SetHashedSubpackets(new PgpSignatureSubpacketVector(
                    plain.GetHashedSubPackets().ToSubpacketArray().Concat(new[]{ critical }).ToArray()));
                signer.Update(Data);
                PgpSignature withCritical = signer.Generate();

                PgpSignature parsed = ((PgpSignatureList)new PgpObjectFactory(withCritical.GetEncoded())
                    .NextPgpObject())[0];
                parsed.InitVerify(pair.PublicKey);
                parsed.Update(Data);

                // TODO[api] Refuse version 4 signatures with an unknown critical subpacket as well
                Assert.That(parsed.Verify(), Is.EqualTo(version == 4 || !isCritical),
                    "version " + version + (isCritical ? ", critical" : "") + (isNotation ? ", notation" : ""));
            }
        }

        // RFC 9580 5.2.5: a version 6 signature of an unknown type does not validate, so none is made
        [Test]
        public void Version6SignaturesOfUnknownTypesAreNotMade()
        {
            PgpKeyPair v6 = EdDsaPair();
            var generator = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha256);
            Assert.Throws<ArgumentException>(() => generator.InitSign(0x42, v6.PrivateKey));
            generator.InitSign(PgpSignature.BinaryDocument, v6.PrivateKey);
        }

        // RFC 9580 5.2.3.7: subpacket lengths have no partial lengths, so a first octet from 192 to 254 starts a
        // two-octet length, up to 16319, and 255 a five-octet one
        [Test]
        public void SubpacketLengths()
        {
            foreach (int length in new[]{ 1, 191, 192, 8383, 8384, 16319, 16320 })
            {
                var encoded = new MemoryStream();
                if (length < 192)
                {
                    encoded.WriteByte((byte)length);
                }
                else if (length <= 16319)
                {
                    encoded.WriteByte((byte)(((length - 192) >> 8) + 192));
                    encoded.WriteByte((byte)(length - 192));
                }
                else
                {
                    encoded.WriteByte(0xFF);
                    encoded.Write(Pack.UInt32_To_BE((uint)length), 0, 4);
                }
                encoded.WriteByte(100);
                encoded.Write(new byte[length - 1], 0, length - 1);
                encoded.Position = 0;

                var parser = new SignatureSubpacketsParser(encoded);
                SignatureSubpacket subpacket = parser.ReadPacket();
                Assert.That((int)subpacket.SubpacketType, Is.EqualTo(100), length.ToString());
                Assert.That(subpacket.GetData().Length, Is.EqualTo(length - 1), length.ToString());
                Assert.That(subpacket.IsLongLength(), Is.EqualTo(length > 16319), length.ToString());
                Assert.That(parser.ReadPacket(), Is.Null, length.ToString());
            }
        }

        // RFC 9580 5.9: the length of the file name is one octet, so a longer name is cut at the start of a character
        [Test]
        public void LongFileNamesOfLiteralData()
        {
            foreach (string name in new[]{ new string('a', 255), new string('a', 256), new string('é', 128) })
            {
                var bOut = new MemoryStream();
                using (Stream literal = new PgpLiteralDataGenerator().Open(bOut, PgpLiteralData.Binary, name,
                    Data.Length, DateTime.UtcNow))
                {
                    literal.Write(Data, 0, Data.Length);
                }

                var parsed = (PgpLiteralData)new PgpObjectFactory(bOut.ToArray()).NextPgpObject();
                byte[] rawName = parsed.GetRawFileName();
                Assert.That(rawName.Length, Is.LessThanOrEqualTo(255), name);
                Assert.That(Strings.ToUtf8ByteArray(name).Take(rawName.Length), Is.EqualTo(rawName), name);
                Assert.That(Strings.FromUtf8ByteArray(rawName).Length,
                    Is.EqualTo(name[0] == 'a' ? 255 : 127), name);
                Assert.That(Streams.ReadAll(parsed.GetInputStream()), Is.EqualTo(Data), name);
            }
        }

        // RFC 9580 5.2.3.24: the lengths of the UTF-8 name and value of a notation are two octets each
        [Test]
        public void NotationsKeepTheirNamesAndValues()
        {
            PgpKeyPair pair = EdDsaPair();
            foreach (string text in new[]{ "é", new string('a', 300), new string('é', 128) })
            {
                string name = text + "@example.org";
                var hashed = new PgpSignatureSubpacketGenerator();
                hashed.AddNotationData(false, true, name, text);
                var generator = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha256);
                generator.InitSign(PgpSignature.BinaryDocument, pair.PrivateKey);
                generator.SetHashedSubpackets(hashed.Generate());
                generator.Update(Data);
                PgpSignature signature = ((PgpSignatureList)new PgpObjectFactory(generator.Generate().GetEncoded())
                    .NextPgpObject())[0];

                NotationData notation = signature.GetHashedSubPackets().GetNotationDataOccurrences(name).Single();
                Assert.That(notation.GetNotationName(), Is.EqualTo(name));
                Assert.That(notation.GetNotationValue(), Is.EqualTo(text));
                Assert.That(notation.GetNotationValueBytes(), Is.EqualTo(Strings.ToUtf8ByteArray(text)));
                signature.InitVerify(pair.PublicKey);
                signature.Update(Data);
                Assert.That(signature.Verify(), Is.True);
            }

            Assert.Throws<ArgumentException>(() => new NotationData(false, true, "name@example.org",
                new string('a', 0x10000)));
        }

        // RFC 9580 5.2.3.23: the deprecated revocation key subpacket is not generated, in version 6 signatures
        [Test]
        public void Version6SignaturesHaveNoRevocationKey()
        {
            PgpKeyPair v6 = EdDsaPair();
            var revocationKey = new RevocationKey(false, RevocationKeyTag.ClassDefault, PublicKeyAlgorithmTag.Ed25519,
                new byte[20]);
            var generator = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha256);
            generator.InitSign(PgpSignature.DirectKey, v6.PrivateKey);
            generator.SetHashedSubpackets(new PgpSignatureSubpacketVector(new SignatureSubpacket[]{ revocationKey }));
            Assert.Throws<PgpException>(() => generator.GenerateCertification(v6.PublicKey));
        }

        // RFC 9580 5.2.3.19: the subpacket of a non-exportable signature is critical
        [Test]
        public void NonExportableSubpacketsAreCritical()
        {
            foreach (bool isExportable in new[]{ false, true })
            {
                var generator = new PgpSignatureSubpacketGenerator();
                generator.SetExportable(false, isExportable);
                SignatureSubpacket exportable = generator.Generate().GetSubpacket(SignatureSubpacketTag.Exportable);
                Assert.That(exportable.IsCritical(), Is.EqualTo(!isExportable), isExportable.ToString());
            }

            // a version 6 certification is refused with a non-critical one that the caller made
            PgpKeyPair v6 = EdDsaPair();
            var custom = new PgpSignatureSubpacketGenerator();
            custom.AddCustomSubpacket(new Exportable(false, false, new byte[]{ 0 }));
            var certifier = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha256);
            certifier.InitSign(PgpSignature.PositiveCertification, v6.PrivateKey);
            certifier.SetHashedSubpackets(custom.Generate());
            Assert.Throws<PgpException>(() => certifier.GenerateCertification("id", v6.PublicKey));
        }

        // RFC 9580 5.4, 5.2.5: a malformed one-pass signature, also a version 6 one with octets after its nested flag,
        // is left out without halting processing or spoiling the other pairs
        [Test]
        public void MalformedOnePassSignaturesDoNotSpoilTheOthers()
        {
            PgpKeyPair pair = EdDsaPair();
            var generator = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha256);
            generator.InitSign(PgpSignature.BinaryDocument, pair.PrivateKey);
            byte[] onePass = generator.GenerateOnePassVersion(false).GetEncoded();
            var literalOut = new MemoryStream();
            using (Stream literal = new PgpLiteralDataGenerator().Open(literalOut, PgpLiteralData.Binary, "",
                Data.Length, DateTime.UtcNow))
            {
                literal.Write(Data, 0, Data.Length);
            }
            generator.Update(Data);
            byte[] signature = generator.Generate().GetEncoded();

            // a salt of sixteen octets announced, and one there; a valid one-pass signature with an octet more; and
            // one in a partial length of 32 octets and the rest (RFC 9580 4.2.1.4)
            byte[] shortened = PgpV6TestUtilities.NewFormatPacket(PacketTag.OnePassSignature,
                new byte[]{ 6, 0, 8, 27, 16, 1 });
            byte[] body = PacketBody(onePass);
            byte[] surplus = PgpV6TestUtilities.NewFormatPacket(PacketTag.OnePassSignature, Arrays.Append(body, 0x42));
            byte[] partial = Arrays.ConcatenateAll(new byte[]{ 0xC0 | (int)PacketTag.OnePassSignature, 0xE0 | 5 },
                Arrays.CopyOf(body, 32), new byte[]{ (byte)(body.Length - 32) }, Arrays.CopyOfRange(body, 32,
                body.Length));

            foreach (byte[] malformed in new[]{ shortened, surplus, partial })
            {
                var factory = new PgpObjectFactory(Arrays.ConcatenateAll(malformed, onePass, literalOut.ToArray(),
                    signature));
                var onePassList = (PgpOnePassSignatureList)factory.NextPgpObject();
                Assert.That(onePassList.Count, Is.EqualTo(1));
                Assert.That(onePassList.UnsupportedCount, Is.EqualTo(1));

                var literal = (PgpLiteralData)factory.NextPgpObject();
                PgpOnePassSignature ops = onePassList[0];
                ops.InitVerify(pair.PublicKey);
                ops.Update(Streams.ReadAll(literal.GetInputStream()));
                var signatures = (PgpSignatureList)factory.NextPgpObject();
                Assert.That(ops.Verify(signatures[0]), Is.True);
            }
        }

        // RFC 9580 5.2.5: a malformed signature is ignored, and does not halt processing or spoil the other signatures
        [Test]
        public void MalformedSignaturesDoNotSpoilTheOthers()
        {
            PgpKeyPair pair = EdDsaPair();
            var generator = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha256);
            generator.InitSign(PgpSignature.BinaryDocument, pair.PrivateKey);
            generator.Update(Data);
            byte[] good = generator.Generate().GetEncoded();

            // the signature value is one octet short of an Ed25519 signature, within a packet of its own
            byte[] body = PacketBody(good);
            byte[] bad = PgpV6TestUtilities.NewFormatPacket(PacketTag.Signature,
                Arrays.CopyOf(body, body.Length - 1));

            foreach (byte[] sequence in new[]
            {
                Arrays.Concatenate(bad, good), Arrays.Concatenate(good, bad), Arrays.ConcatenateAll(bad, bad, good),
            })
            {
                var signatures = (PgpSignatureList)new PgpObjectFactory(sequence).NextPgpObject();
                Assert.That(signatures.Count, Is.EqualTo(1));
                signatures[0].InitVerify(pair.PublicKey);
                signatures[0].Update(Data);
                Assert.That(signatures[0].Verify(), Is.True);
            }

            // among the signatures of a certificate
            generator.InitSign(PgpSignature.DirectKey, pair.PrivateKey);
            byte[] directKey = generator.GenerateCertification(pair.PublicKey).GetEncoded();
            var ring = new PgpPublicKeyRing(Arrays.ConcatenateAll(pair.PublicKey.PublicKeyPacket.GetEncoded(), bad,
                directKey));
            PgpSignature signature = ring.GetPublicKey().GetKeySignatures().Cast<PgpSignature>().Single();
            signature.InitVerify(ring.GetPublicKey());
            Assert.That(signature.VerifyCertification(ring.GetPublicKey()), Is.True);
        }

        // RFC 9580 4.3: an unknown non-critical packet is ignored, also within a certificate or a secret key
        [Test]
        public void UnknownNonCriticalPacketsInKeysAreIgnored()
        {
            byte[] unknown = PgpV6TestUtilities.NewFormatPacket((PacketTag)40, new byte[]{ 1 });
            foreach (bool isSecret in new[]{ false, true })
            {
                byte[] original = PgpV6TestUtilities.LoadRfc9580(isSecret
                    ? "a4-v6-secret-key.asc" : "a3-v6-certificate.asc");
                byte[] expected = isSecret
                    ? new PgpSecretKeyRing(original).GetEncoded()
                    : new PgpPublicKeyRing(original).GetEncoded();
                byte[][] packets = PgpUnsupportedVersionTest.SplitPackets(original);
                for (int i = 1; i <= packets.Length; ++i)
                {
                    byte[] changed = Arrays.ConcatenateAll(
                        packets.Take(i).Concat(new[]{ unknown }).Concat(packets.Skip(i)).ToArray());
                    byte[] parsed = isSecret
                        ? new PgpSecretKeyRing(changed).GetEncoded()
                        : new PgpPublicKeyRing(changed).GetEncoded();
                    Assert.That(parsed, Is.EqualTo(expected), (isSecret ? "secret, " : "public, ") + i);
                }
            }

            // and between signatures
            PgpKeyPair pair = EdDsaPair();
            var generator = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha256);
            generator.InitSign(PgpSignature.BinaryDocument, pair.PrivateKey);
            generator.Update(Data);
            byte[] signature = generator.Generate().GetEncoded();
            var signatures = (PgpSignatureList)new PgpObjectFactory(Arrays.ConcatenateAll(signature, unknown,
                signature)).NextPgpObject();
            Assert.That(signatures.Count, Is.EqualTo(2));
        }

        // RFC 9580 5.2.4: a signature covers its hashed subpackets as they are encoded in the packet: a valid encoding
        // that is not the one used here still verifies, and a changed one that the parser accepts does not
        [Test]
        public void SignaturesCoverTheHashedSubpacketsAsEncoded()
        {
            PgpKeyPair pair = EdDsaPair();
            byte[] fingerprint = Arrays.Prepend(pair.PublicKey.GetFingerprint(), 6);
            byte[] issuer = Arrays.ConcatenateAll(new byte[]{ (byte)(1 + fingerprint.Length), 33 }, fingerprint);
            byte[] time = Pack.UInt32_To_BE((uint)(DateTimeUtilities.CurrentUnixMs() / 1000));
            byte[] creationTime = Arrays.ConcatenateAll(new byte[]{ 5, 2 }, time);

            // an unknown non-critical subpacket of 8384 octets in a two-octet length, which is written in five here
            byte[] large = Arrays.ConcatenateAll(new byte[]{ 0xE0, 0x00, 100 }, new byte[8383]);
            byte[] area = Arrays.ConcatenateAll(issuer, creationTime, large);
            Assert.That(VerifyRawSignature(pair, area, area), Is.True);

            // the length of the last subpacket, the creation time, raised beyond the end of the area
            area = Arrays.Concatenate(issuer, creationTime);
            byte[] changed = Arrays.Clone(area);
            changed[issuer.Length] = 6;
            Assert.That(VerifyRawSignature(pair, area, area), Is.True);
            Assert.That(VerifyRawSignature(pair, area, changed), Is.False);

            // nor is an unhashed creation time that is shorter than its length says taken at its fixed length
            Assert.That(VerifyRawSignature(pair, area, area, creationTime), Is.True);
            byte[] shortened = Arrays.Clone(creationTime);
            shortened[0] = 6;
            Assert.That(VerifyRawSignature(pair, area, area, shortened), Is.False);
        }

        // Verify a version 6 Ed25519 signature over Data, made over the first hashed subpacket area and sent with the
        // second, and the given unhashed area
        private static bool VerifyRawSignature(PgpKeyPair pair, byte[] signedArea, byte[] sentArea,
            byte[] unhashedArea = null)
        {
            unhashedArea = unhashedArea ?? new byte[0];
            byte[] salt = SecureRandom.GetNextBytes(Random, 16);
            byte[] header = Arrays.Concatenate(new byte[]{ 6, PgpSignature.BinaryDocument,
                (byte)PublicKeyAlgorithmTag.Ed25519, (byte)HashAlgorithmTag.Sha256 },
                Pack.UInt32_To_BE((uint)signedArea.Length));
            byte[] trailer = Arrays.ConcatenateAll(header, signedArea, new byte[]{ 6, 0xFF },
                Pack.UInt32_To_BE((uint)(header.Length + signedArea.Length)));
            byte[] hashValue = DigestUtilities.DoFinal(PgpUtilities.CreateDigest(HashAlgorithmTag.Sha256),
                Arrays.ConcatenateAll(salt, Data, trailer));
            ISigner signer = new Ed25519Signer();
            signer.Init(true, pair.PrivateKey.Key);
            signer.BlockUpdate(hashValue, 0, hashValue.Length);

            byte[] body = Arrays.ConcatenateAll(
                Arrays.CopyOf(header, 4), Pack.UInt32_To_BE((uint)sentArea.Length), sentArea,
                Pack.UInt32_To_BE((uint)unhashedArea.Length), unhashedArea,
                Arrays.CopyOf(hashValue, 2), new byte[]{ (byte)salt.Length }, salt, signer.GenerateSignature());
            try
            {
                var signatures = (PgpSignatureList)new PgpObjectFactory(
                    PgpV6TestUtilities.NewFormatPacket(PacketTag.Signature, body)).NextPgpObject();
                if (signatures.Count == 0)
                    return false;

                signatures[0].InitVerify(pair.PublicKey);
                signatures[0].Update(Data);
                return signatures[0].Verify();
            }
            catch (Exception e) when (e is IOException || e is PgpException)
            {
                return false;
            }
        }

        // RFC 9580 5.2.3.12: the signer of a version 6 signature does not include an issuer key ID, so one in the
        // hashed area makes it malformed (one in the unhashed area, which anyone can add, is tolerated)
        [Test]
        public void HashedIssuerKeyIdsMakeVersion6SignaturesMalformed()
        {
            PgpKeyPair pair = EdDsaPair();
            var creationTime = new SignatureCreationTime(false, DateTime.UtcNow);
            var fingerprint = new IssuerFingerprint(false, 6, pair.PublicKey.GetFingerprint());
            Assert.That(VerifyRawVersion6Signature(pair, PgpSignature.BinaryDocument, new SignatureSubpacket[]
            {
                creationTime, fingerprint,
            }), Is.True);
            Assert.That(VerifyRawVersion6Signature(pair, PgpSignature.BinaryDocument, new SignatureSubpacket[]
            {
                creationTime, fingerprint, new IssuerKeyId(false, pair.KeyId),
            }), Is.False);
        }

        // RFC 9580 5.2.5: a subpacket with a length that diverges from the expected length makes a version 6
        // signature malformed
        [Test]
        public void Version6SubpacketsHaveTheirLengths()
        {
            PgpKeyPair pair = EdDsaPair();
            var creationTime = new SignatureCreationTime(false, DateTime.UtcNow);
            var fingerprint = new IssuerFingerprint(false, 6, pair.PublicKey.GetFingerprint());

            bool Verifies(SignatureSubpacketTag type, int length) => VerifyRawVersion6Signature(pair,
                PgpSignature.BinaryDocument, new SignatureSubpacket[]
                {
                    creationTime, fingerprint, new SignatureSubpacket(type, false, false, new byte[length]),
                });

            foreach (var (type, length) in new[]
            {
                (SignatureSubpacketTag.PrimaryUserId, 1), (SignatureSubpacketTag.TrustSig, 2),
                (SignatureSubpacketTag.Revocable, 1), (SignatureSubpacketTag.PreferredAeadAlgorithms, 4),
            })
            {
                Assert.That(Verifies(type, length), Is.True, type + ", " + length);
                foreach (int other in new[]{ length - 1, length + 1 })
                {
                    Assert.That(Verifies(type, other), Is.False, type + ", " + other);
                }
            }

            // a signature target with a SHA-256 digest of another size
            foreach (int size in new[]{ 32, 0, 31, 33 })
            {
                byte[] target = Arrays.Concatenate(new byte[]{ (byte)PublicKeyAlgorithmTag.Ed25519,
                    (byte)HashAlgorithmTag.Sha256 }, new byte[size]);
                Assert.That(VerifyRawVersion6Signature(pair, PgpSignature.BinaryDocument, new SignatureSubpacket[]
                {
                    creationTime, fingerprint,
                    new SignatureSubpacket(SignatureSubpacketTag.SignatureTarget, false, false, target),
                }), Is.EqualTo(size == 32), "signature target of " + size);
            }

            // a notation with an octet after its value
            var notation = new NotationData(false, true, "name@example.org", "value");
            Assert.That(Verifies(SignatureSubpacketTag.NotationData, 0), Is.False);
            Assert.That(VerifyRawVersion6Signature(pair, PgpSignature.BinaryDocument, new SignatureSubpacket[]
            {
                creationTime, fingerprint, notation,
            }), Is.True);
            Assert.That(VerifyRawVersion6Signature(pair, PgpSignature.BinaryDocument, new SignatureSubpacket[]
            {
                creationTime, fingerprint, new SignatureSubpacket(SignatureSubpacketTag.NotationData, false, false,
                    Arrays.Append(notation.GetData(), 0)),
            }), Is.False);
        }

        // The body of a packet with a new-format header and a definite length
        private static byte[] PacketBody(byte[] packet)
        {
            int offset = packet[1] < 192 ? 2 : packet[1] < 224 ? 3 : 6;
            return Arrays.CopyOfRange(packet, offset, packet.Length);
        }

        // RFC 9580 5.5.2.3, 5.3.2, 5.2.3: the lengths in version 6 packets are exact. A key material length that
        // differs from the material, an S2K length that differs from the S2K specifier, and octets after the
        // signature value are all malformed
        [Test]
        public void Version6LengthsAreExact()
        {
            var rsaGenerator = new RsaKeyPairGenerator();
            rsaGenerator.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(0x10001), Random, 2048, 25));
            var rsa = new PgpKeyPair(6, PublicKeyAlgorithmTag.RsaGeneral, rsaGenerator.GenerateKeyPair(),
                DateTime.UtcNow);

            // the key material of RSA keys does not end by itself
            byte[] body = rsa.PublicKey.PublicKeyPacket.GetEncodedContents();
            int length = (int)Pack.BE_To_UInt32(body, 6);
            foreach (int count in new[]{ 1, length - 1, length + 1 })
            {
                byte[] changed = Arrays.Clone(body);
                Pack.UInt32_To_BE((uint)count, changed, 6);
                Assert.Catch<IOException>(() => PgpV6TestUtilities.ReadPacket<PublicKeyPacket>(
                    PgpV6TestUtilities.NewFormatPacket(PacketTag.PublicKey, changed)), count.ToString());
            }
            var exact = new PgpPublicKey(PgpV6TestUtilities.ReadPacket<PublicKeyPacket>(
                PgpV6TestUtilities.NewFormatPacket(PacketTag.PublicKey, body)));
            Assert.That(exact.GetFingerprint(), Is.EqualTo(rsa.PublicKey.GetFingerprint()));

            // nor does the packet go on after the key material, which the fingerprint would not cover
            foreach (PacketTag tag in new[]{ PacketTag.PublicKey, PacketTag.PublicSubkey })
            {
                Assert.Catch<IOException>(() => PgpV6TestUtilities.ReadPacket<PublicKeyPacket>(
                    PgpV6TestUtilities.NewFormatPacket(tag, Arrays.Append(body, 0))), tag.ToString());
            }

            // the S2K length of a version 6 SKESK, raised together with the length of all its fields
            var encryptor = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes128, AeadAlgorithmTag.Ocb,
                Random);
            encryptor.AddMethodUtf8("password".ToCharArray(), HashAlgorithmTag.Sha256);
            var bOut = new MemoryStream();
            using (Stream encOut = encryptor.Open(bOut, Data.Length))
            {
                encOut.Write(Data, 0, Data.Length);
            }
            byte[][] packets = PgpUnsupportedVersionTest.SplitPackets(bOut.ToArray());
            byte[] skesk = PacketBody(packets[0]);
            Assert.That(Decrypts(packets), Is.True);
            skesk[1]++;
            skesk[4]++;
            packets[0] = PgpV6TestUtilities.NewFormatPacket(PacketTag.SymmetricKeyEncryptedSessionKey, skesk);
            Assert.That(Decrypts(packets), Is.False);

            // octets after the value of a signature of MPIs
            var generator = new PgpSignatureGenerator(PublicKeyAlgorithmTag.RsaGeneral, HashAlgorithmTag.Sha256);
            generator.InitSign(PgpSignature.BinaryDocument, rsa.PrivateKey);
            generator.Update(Data);
            byte[] signature = generator.Generate().GetEncoded();
            Assert.That(VerifiesData(signature, rsa.PublicKey), Is.True);
            byte[] longer = Arrays.Concatenate(PacketBody(signature), new byte[2]);
            Assert.That(VerifiesData(PgpV6TestUtilities.NewFormatPacket(PacketTag.Signature, longer), rsa.PublicKey),
                Is.False);
        }

        // RFC 9580 11.5.1: no message is encrypted to a version 6 ECDH key with other KDF or KEK parameters than its
        // curve requires, in version 1 SEIPD messages as in version 2 ones
        [Test]
        public void Version6EcdhKeysNeedTheParametersOfTheirCurve()
        {
            var generator = new ECKeyPairGenerator("ECDH");
            generator.Init(new ECKeyGenerationParameters(SecObjectIdentifiers.SecP384r1, Random));
            var ec = (ECPublicKeyParameters)generator.GenerateKeyPair().Public;

            foreach (var (hash, wrap, valid) in new[]
            {
                (HashAlgorithmTag.Sha256, SymmetricKeyAlgorithmTag.Aes128, false),
                (HashAlgorithmTag.Sha384, SymmetricKeyAlgorithmTag.Aes128, false),
                (HashAlgorithmTag.Sha384, SymmetricKeyAlgorithmTag.Aes192, true),
            })
            {
                var key = new PgpPublicKey(new PublicKeyPacket(6, PublicKeyAlgorithmTag.ECDH, DateTime.UtcNow,
                    new ECDHPublicBcpgKey(SecObjectIdentifiers.SecP384r1, ec.Q, hash, wrap)));
                foreach (var encryptor in new[]
                {
                    new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, true, Random),
                    new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, AeadAlgorithmTag.Ocb, Random),
                })
                {
                    if (valid)
                    {
                        encryptor.AddMethod(key);
                    }
                    else
                    {
                        Assert.Throws<PgpException>(() => encryptor.AddMethod(key), hash + ", " + wrap);
                    }
                }
            }
        }

        // RFC 9580 5.1: nothing follows the wrapped session key in a version 6 PKESK to an ECDH key
        [Test]
        public void Version6EcdhSessionKeysHaveNoTrailingData()
        {
            var ecdh = new ECKeyPairGenerator("ECDH");
            ecdh.Init(new ECKeyGenerationParameters(SecObjectIdentifiers.SecP256r1, Random));
            var pair = new PgpKeyPair(6, PublicKeyAlgorithmTag.ECDH, ecdh.GenerateKeyPair(), DateTime.UtcNow);

            var encryptor = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, AeadAlgorithmTag.Ocb,
                Random);
            encryptor.AddMethod(pair.PublicKey);
            var bOut = new MemoryStream();
            using (Stream encOut = encryptor.Open(bOut, Data.Length))
            {
                encOut.Write(Data, 0, Data.Length);
            }
            byte[][] packets = PgpUnsupportedVersionTest.SplitPackets(bOut.ToArray());

            bool Decrypts(byte[] pkesk)
            {
                var list = (PgpEncryptedDataList)new PgpObjectFactory(Arrays.Concatenate(pkesk, packets[1]))
                    .NextPgpObject();
                var encrypted = (PgpPublicKeyEncryptedData)list[0];
                try
                {
                    return Arrays.AreEqual(Streams.ReadAll(encrypted.GetDataStream(pair.PrivateKey)), Data);
                }
                catch (Exception e) when (e is PgpException || e is IOException)
                {
                    return false;
                }
            }

            Assert.That(Decrypts(packets[0]), Is.True);
            Assert.That(Decrypts(PgpV6TestUtilities.NewFormatPacket(PacketTag.PublicKeyEncryptedSession,
                Arrays.Append(PacketBody(packets[0]), 0x42))), Is.False);
        }

        // RFC 9580 4.2.1.4: the first partial body length is at least 512 octets, also with a smaller (or empty)
        // buffer, and partial body lengths are only for data packets
        [TestCase(8)]
        [TestCase(0)]
        public void PartialBodiesStartWith512Octets(int bufferSize)
        {
            byte[] content = SecureRandom.GetNextBytes(Random, 600);
            var bOut = new MemoryStream();
            using (Stream litOut = new PgpLiteralDataGenerator().Open(bOut, PgpLiteralData.Binary, "", DateTime.UtcNow,
                new byte[bufferSize]))
            {
                litOut.Write(content, 0, content.Length);
            }
            byte[] packet = bOut.ToArray();
            Assert.That(packet[1], Is.EqualTo(0xE0 | 9));

            var literal = (PgpLiteralData)new PgpObjectFactory(packet).NextPgpObject();
            Assert.That(Streams.ReadAll(literal.GetInputStream()), Is.EqualTo(content));

            Assert.Throws<ArgumentException>(() => new BcpgOutputStream(new MemoryStream(), PacketTag.Signature,
                new byte[512]));
        }

        // RFC 9580 4.2.1.4: partial lengths end with a definite length, without which the packet is truncated
        [Test]
        public void PartialBodiesEndWithADefiniteLength()
        {
            byte[] content = SecureRandom.GetNextBytes(Random, 600);
            var bOut = new MemoryStream();
            using (Stream litOut = new PgpLiteralDataGenerator().Open(bOut, PgpLiteralData.Binary, "", DateTime.UtcNow,
                new byte[512]))
            {
                litOut.Write(content, 0, content.Length);
            }
            byte[] packet = bOut.ToArray();

            // the tag, the partial length of 512 octets and those octets, but not the rest
            var literal = (PgpLiteralData)new PgpObjectFactory(Arrays.CopyOf(packet, 2 + 512)).NextPgpObject();
            Assert.Catch<IOException>(() => Streams.ReadAll(literal.GetInputStream()));
        }

        // RFC 9580 4.2.1.4: partial lengths are only for data packets, not for version 6 signatures or keys
        [Test]
        public void Version6SignaturesAndKeysHaveDefiniteLengths()
        {
            // the contents in a part of 2^power octets, then the rest with a definite length (less than 192 octets)
            byte[] Partial(PacketTag tag, byte[] contents, int power) => Arrays.ConcatenateAll(
                new byte[]{ (byte)(0xC0 | (int)tag), (byte)(0xE0 | power) }, Arrays.CopyOf(contents, 1 << power),
                new byte[]{ (byte)(contents.Length - (1 << power)) },
                Arrays.CopyOfRange(contents, 1 << power, contents.Length));

            PgpKeyPair pair = EdDsaPair();
            var generator = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha256);
            generator.InitSign(PgpSignature.BinaryDocument, pair.PrivateKey);
            generator.Update(Data);
            byte[] body = PacketBody(generator.Generate().GetEncoded());
            Assert.That(body.Length, Is.InRange(65, 64 + 191));

            foreach (bool partial in new[]{ false, true })
            {
                byte[] packet = partial
                    ? Partial(PacketTag.Signature, body, 6)
                    : PgpV6TestUtilities.NewFormatPacket(PacketTag.Signature, body);
                var signatures = (PgpSignatureList)new PgpObjectFactory(packet).NextPgpObject();
                signatures[0].InitVerify(pair.PublicKey);
                signatures[0].Update(Data);
                Assert.That(signatures[0].Verify(), Is.EqualTo(!partial), "partial: " + partial);
            }

            byte[] keyBody = pair.PublicKey.PublicKeyPacket.GetEncodedContents();
            Assert.That(keyBody.Length, Is.InRange(33, 32 + 191));
            Assert.Catch<IOException>(() => PgpV6TestUtilities.ReadPacket<PublicKeyPacket>(
                Partial(PacketTag.PublicKey, keyBody, 5)));
        }

        // RFC 9580 3.2: the MPIs of version 6 keys are minimal, also those of the secret key material
        [Test]
        public void Version6SecretMpisAreMinimal()
        {
            var ecdsa = new ECKeyPairGenerator("ECDSA");
            ecdsa.Init(new ECKeyGenerationParameters(ECNamedCurveTable.GetOid("P-256"), Random));
            var pair = new PgpKeyPair(6, PublicKeyAlgorithmTag.ECDsa, ecdsa.GenerateKeyPair(), DateTime.UtcNow);
            PgpSecretKey key = new PgpKeyRingGenerator(pair, HashAlgorithmTag.Sha256, null, null,
                PgpSecretKeyProtection.None, Random).GenerateSecretKeyRing().GetSecretKey();
            Assert.That(key.ExtractPrivateKey(null), Is.Not.Null);

            // the secret scalar, an MPI with no checksum after it, prefixed with a zero octet that the bit count
            // includes
            var packet = (SecretKeyPacket)BcpgInputStream.Wrap(new MemoryStream(key.GetEncoded(), false))
                .ReadPacket();
            byte[] mpi = packet.GetSecretKeyData();
            int bits = 8 * (mpi.Length - 2 + 1);
            byte[] inflated = Arrays.ConcatenateAll(new byte[]{ (byte)(bits >> 8), (byte)bits, 0x00 },
                Arrays.CopyOfRange(mpi, 2, mpi.Length));
            var changed = new PgpSecretKey(new SecretKeyPacket(packet.PublicKeyPacket, SymmetricKeyAlgorithmTag.Null,
                null, null, inflated), key.PublicKey);
            Assert.Throws<PgpException>(() => changed.ExtractPrivateKey(null));
        }

        // RFC 9580 5.5.3: the key material accounts for the whole cleartext of encrypted key material, of any version
        [Test]
        public void EncryptedSecretKeyMaterialHasNoTrailingData()
        {
            var ecdsa = new ECKeyGenerationParameters(ECNamedCurveTable.GetOid("P-256"), Random);
            var generator = new ECKeyPairGenerator("ECDSA");
            generator.Init(ecdsa);
            var pair = new PgpKeyPair(4, PublicKeyAlgorithmTag.ECDsa, generator.GenerateKeyPair(), DateTime.UtcNow);
            PgpSecretKey key = new PgpKeyRingGenerator(pair, HashAlgorithmTag.Sha256, null, null,
                PgpSecretKeyProtection.None, Random).GenerateSecretKeyRing().GetSecretKey();

            // the secret scalar with an extra octet after it, and the checksum over both
            var packet = (SecretKeyPacket)BcpgInputStream.Wrap(new MemoryStream(key.GetEncoded(), false))
                .ReadPacket();
            byte[] data = packet.GetSecretKeyData();
            byte[] material = Arrays.Append(Arrays.CopyOfRange(data, 0, data.Length - 2), 0x42);
            int checksum = material.Sum(b => b) & 0xFFFF;
            var lenient = new PgpSecretKey(new SecretKeyPacket(packet.PublicKeyPacket, SymmetricKeyAlgorithmTag.Null,
                null, null, Arrays.Concatenate(material, new byte[]{ (byte)(checksum >> 8), (byte)checksum })),
                key.PublicKey);

            // unencrypted version 4 key material of an older algorithm is decoded leniently, but not once encrypted
            Assert.That(lenient.ExtractPrivateKey(null), Is.Not.Null);
            PgpSecretKey encrypted = PgpSecretKey.CopyWithNewPassword(lenient, null, "secret".ToCharArray(),
                SymmetricKeyAlgorithmTag.Aes256, Random);
            Assert.That(encrypted.S2kUsage, Is.EqualTo(SecretKeyPacket.UsageSha1));
            Assert.Throws<PgpException>(() => encrypted.ExtractPrivateKey("secret".ToCharArray()));
        }

        private static bool Decrypts(byte[][] packets)
        {
            try
            {
                var list = (PgpEncryptedDataList)new PgpObjectFactory(Arrays.ConcatenateAll(packets)).NextPgpObject();
                var encrypted = list.GetEncryptedDataObjects().OfType<PgpPbeEncryptedData>().FirstOrDefault();
                return encrypted != null &&
                    Arrays.AreEqual(Streams.ReadAll(encrypted.GetDataStreamUtf8("password".ToCharArray())), Data);
            }
            catch (Exception e) when (e is IOException || e is PgpException)
            {
                return false;
            }
        }

        private static bool VerifiesData(byte[] signatureEncoding, PgpPublicKey key)
        {
            PgpSignature signature = ((PgpSignatureList)new PgpObjectFactory(signatureEncoding).NextPgpObject())[0];
            signature.InitVerify(key);
            signature.Update(Data);
            return signature.Verify();
        }

        // RFC 9580 5.2.3.11, 5.2.5: version 6 signatures without a hashed creation time, or of an unknown type, are
        // not validated
        [Test]
        public void Version6SignaturesNeedACreationTimeAndAKnownType()
        {
            PgpKeyPair pair = EdDsaPair();
            var fingerprint = new IssuerFingerprint(false, 6, pair.PublicKey.GetFingerprint());

            // a valid signature value over a signature with only the issuer fingerprint in its hashed area
            Assert.That(VerifyRawVersion6Signature(pair, PgpSignature.BinaryDocument, new SignatureSubpacket[]
            {
                fingerprint,
            }), Is.False);
            Assert.That(VerifyRawVersion6Signature(pair, PgpSignature.BinaryDocument, new SignatureSubpacket[]
            {
                new SignatureCreationTime(false, DateTime.UtcNow), fingerprint,
            }), Is.True);

            // an unassigned signature type
            Assert.That(VerifyRawVersion6Signature(pair, 0x42, new SignatureSubpacket[]
            {
                new SignatureCreationTime(false, DateTime.UtcNow), fingerprint,
            }), Is.False);
        }

        // Verify a version 6 Ed25519 signature over Data with the given hashed subpackets, made with the signer of
        // the library itself, so that the generator does not add a creation time
        private static bool VerifyRawVersion6Signature(PgpKeyPair pair, int type, SignatureSubpacket[] hashed)
        {
            byte[] salt = SecureRandom.GetNextBytes(Random, 16);
            var unhashed = new SignatureSubpacket[0];
            byte[] trailer = new SignaturePacket(6, true, type, pair.KeyId, PublicKeyAlgorithmTag.Ed25519,
                HashAlgorithmTag.Sha256, hashed, unhashed, new byte[2], salt, null, new byte[64]).GetSignatureTrailer();

            byte[] hashValue = DigestUtilities.DoFinal(PgpUtilities.CreateDigest(HashAlgorithmTag.Sha256),
                Arrays.ConcatenateAll(salt, Data, trailer));
            ISigner signer = new Ed25519Signer();
            signer.Init(true, pair.PrivateKey.Key);
            signer.BlockUpdate(hashValue, 0, hashValue.Length);

            // a signature that cannot be parsed is left out (RFC 9580 5.2.5)
            var signatures = (PgpSignatureList)new PgpObjectFactory(new SignaturePacket(6, true, type,
                pair.KeyId, PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha256, hashed, unhashed,
                new byte[]{ hashValue[0], hashValue[1] }, salt, null, signer.GenerateSignature()).GetEncoded())
                .NextPgpObject();
            if (signatures.Count == 0)
                return false;

            PgpSignature signature = signatures[0];
            signature.InitVerify(pair.PublicKey);
            signature.Update(Data);
            return signature.Verify();
        }

        private sealed class MixedCertificate
        {
            internal PgpPublicKeyRing Public;
            internal PgpSecretKeyRing Secret;
            internal PgpPublicKey UnknownSubkey;
            internal PgpPublicKey X25519Subkey;
        }

        /// <summary>A certificate with a subkey of the (not defined) algorithm 37 and an X25519 subkey.</summary>
        private static MixedCertificate NewMixedCertificate()
        {
            PgpKeyPair primary = EdDsaPair();
            var generator = new PgpKeyRingGenerator(primary, HashAlgorithmTag.Sha256, Flags(PgpKeyFlags.CanCertify),
                null, PgpSecretKeyProtection.None, Random);
            generator.AddUserId("mixed", PgpSignature.PositiveCertification, null, null);
            generator.AddSubKey(X25519Pair(), Flags(PgpKeyFlags.CanEncryptCommunications), null);

            PgpPublicKeyRing ring = generator.GeneratePublicKeyRing();
            PgpPublicKey[] keys = ring.GetPublicKeys().ToArray();

            // the subkey of algorithm 37, bound to the primary key by a valid signature
            var packet = new PublicSubkeyPacket(6, (PublicKeyAlgorithmTag)37, DateTime.UtcNow,
                new UnknownBcpgKey(64, new byte[64]));
            var unknown = new PgpPublicKey(packet);

            var binder = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha256);
            binder.InitSign(PgpSignature.SubkeyBinding, primary.PrivateKey);
            binder.SetHashedSubpackets(Flags(PgpKeyFlags.CanEncryptCommunications));
            PgpSignature binding = binder.GenerateCertification(keys[0], unknown);
            unknown = new PgpPublicKey(unknown, null, new List<PgpSignature>{ binding });

            return new MixedCertificate
            {
                Public = new PgpPublicKeyRing(new[]{ keys[0], unknown, keys[1] }),
                Secret = generator.GenerateSecretKeyRing(),
                UnknownSubkey = unknown,
                X25519Subkey = keys[1],
            };
        }

        [Test]
        public void UnknownSubkeyAlgorithmDoesNotBreakTheCertificate()
        {
            MixedCertificate cert = NewMixedCertificate();
            var reloaded = new PgpPublicKeyRing(cert.Public.GetEncoded());

            PgpPublicKey[] keys = reloaded.GetPublicKeys().ToArray();
            Assert.That(keys.Length, Is.EqualTo(3));
            Assert.That((int)keys[1].Algorithm, Is.EqualTo(37));
            Assert.That(keys[1].IsEncryptionKey, Is.False);
            Assert.Throws<PgpException>(() => keys[1].GetKey());

            // the binding of the unknown subkey is a valid signature
            PgpSignature binding = keys[1].GetSignaturesOfType(PgpSignature.SubkeyBinding).Cast<PgpSignature>()
                .Single();
            binding.InitVerify(keys[0]);
            Assert.That(binding.VerifyCertification(keys[0], keys[1]), Is.True);

            // the preferences ignore it, and a message goes to the X25519 key
            PgpEncryptionPreferences preferences = PgpEncryptionPreferences.Select(new[]{ reloaded });
            PgpEncryptedDataGenerator encrypter = preferences.CreateGenerator(Random);
            encrypter.AddMethod(keys.First(k => k.IsEncryptionKey));
            Assert.That(keys.Count(k => k.IsEncryptionKey), Is.EqualTo(1));
            Assert.That(keys.First(k => k.IsEncryptionKey).Algorithm, Is.EqualTo(PublicKeyAlgorithmTag.X25519));
        }

        [Test]
        public void UnknownAlgorithmsNextToUsableOnes()
        {
            MixedCertificate cert = NewMixedCertificate();
            byte[] message = PgpV6PkeskTest.EncryptV2(new[]{ cert.X25519Subkey }, Data);
            byte[][] packets = PgpUnsupportedVersionTest.SplitPackets(message);

            // a PKESK for the unknown subkey in front of the one that works
            var unknownPkesk = PublicKeyEncSessionPacket.CreateV6Packet(6, cert.UnknownSubkey.GetFingerprint(),
                (PublicKeyAlgorithmTag)37, new[]{ new byte[48] });
            byte[] both = Arrays.ConcatenateAll(unknownPkesk.GetEncoded(), packets[0], packets[1]);

            PgpPrivateKey privateKey = cert.Secret.GetSecretKeys().Last().ExtractPrivateKey(null);
            var list = (PgpEncryptedDataList)new PgpObjectFactory(both).NextPgpObject();
            Assert.That(list.Count, Is.EqualTo(2));
            Assert.That(PgpMLKemX25519Test.Decrypt(both, privateKey).Content, Is.EqualTo(Data));

            // a signature of an unknown algorithm in front of a valid one
            PgpKeyPair signingPair = EdDsaPair();
            var signer = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha256);
            signer.InitSign(PgpSignature.BinaryDocument, signingPair.PrivateKey);
            signer.Update(Data);
            PgpSignature valid = signer.Generate();

            var unknownSignature = new SignaturePacket(6, true, PgpSignature.BinaryDocument, 0,
                (PublicKeyAlgorithmTag)99, HashAlgorithmTag.Sha256, new SignatureSubpacket[0],
                new SignatureSubpacket[0], new byte[2], new byte[16], null, new byte[80]);

            byte[] signatures = Arrays.Concatenate(unknownSignature.GetEncoded(), valid.GetEncoded());
            var parsed = (PgpSignatureList)new PgpObjectFactory(signatures).NextPgpObject();
            Assert.That(parsed.Count, Is.EqualTo(2));

            parsed[0].InitVerify(signingPair.PublicKey);
            parsed[0].Update(Data);
            Assert.That(parsed[0].Verify(), Is.False);

            parsed[1].InitVerify(signingPair.PublicKey);
            parsed[1].Update(Data);
            Assert.That(parsed[1].Verify(), Is.True);
        }

        /// <summary>
        /// The algorithms that are mandatory to implement (RFC 9580 9.1 to 9.6) in one message: Ed25519,
        /// X25519, AES-128, OCB, SHA2-256, no compression, version 6 formats.
        /// </summary>
        [Test]
        public void MandatoryToImplementAlgorithmsEndToEnd()
        {
            PgpKeyPair signing = EdDsaPair();
            PgpKeyPair encryption = X25519Pair();

            var generator = new PgpKeyRingGenerator(signing, HashAlgorithmTag.Sha256, Flags(PgpKeyFlags.CanCertify |
                PgpKeyFlags.CanSign), null, PgpSecretKeyProtection.None, Random);
            generator.AddSubKey(encryption, Flags(PgpKeyFlags.CanEncryptCommunications), null);
            PgpPublicKeyRing publicRing = generator.GeneratePublicKeyRing();
            PgpSecretKeyRing secretRing = generator.GenerateSecretKeyRing();

            // sign (version 6 one-pass signature and signature, SHA2-256), then encrypt (version 6 PKESK, SEIPD v2
            // with AES-128 and OCB, one chunk of the default size)
            var bOut = new MemoryStream();
            var encrypter = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes128, AeadAlgorithmTag.Ocb,
                Random);
            encrypter.AddMethod(publicRing.GetPublicKeys().Last());
            using (Stream encrypted = encrypter.Open(bOut, new byte[1 << 10]))
            {
                var signer = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha256);
                signer.InitSign(PgpSignature.BinaryDocument, secretRing.GetSecretKey().ExtractPrivateKey(null));
                signer.GenerateOnePassVersion(false).Encode(encrypted);

                using (Stream literal = new PgpLiteralDataGenerator().Open(encrypted, PgpLiteralData.Binary, "",
                    Data.Length, DateTime.UtcNow))
                {
                    literal.Write(Data, 0, Data.Length);
                }

                signer.Update(Data);
                signer.Generate().Encode(encrypted);
            }

            byte[] message = bOut.ToArray();
            var list = (PgpEncryptedDataList)new PgpObjectFactory(message).NextPgpObject();
            var encryptedData = (PgpPublicKeyEncryptedData)list[0];
            Assert.That(encryptedData.Version, Is.EqualTo(6));
            Assert.That(encryptedData.IsAead, Is.True);

            PgpMLKemX25519Test.Decrypted result = PgpMLKemX25519Test.Decrypt(message,
                secretRing.GetSecretKeys().Last().ExtractPrivateKey(null), publicRing.GetPublicKey());
            Assert.That(result.Content, Is.EqualTo(Data));
            Assert.That(result.Algorithm, Is.EqualTo(SymmetricKeyAlgorithmTag.Aes128));
            Assert.That(result.IntegrityVerified, Is.True);
            Assert.That(result.SignatureVerified, Is.True);
        }
    }
}
