using System;
using System.Linq;

using NUnit.Framework;

using Org.BouncyCastle.Bcpg.Sig;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    /// <summary>Tests for the verification of version 6 signatures (RFC 9580 5.2.3, 5.2.4).</summary>
    [TestFixture]
    public class PgpV6SignatureVerificationTest
    {
        // The data that the direct key signature of RFC 9580 A.3 is made over (A.3.1)
        private const string Rfc9580A3DirectKeyHashedData =
            "103e2d7d227ec0e6d7ce4471db36bfc97083253690271498a7ef0576c07faae19b0000002a0663877fe31b00000020f94da7bb48"
            + "d60a61e567706a6587d0331999bb9d891a08242ead84543df895a3061f1b0a00000042058263877fe3030b090705150a0e080c02"
            + "1600029b03021e09222106cb186c4f0609a697e4d52dfa6c722b0c1f1e27c18a56708f6525ec27bad9acc905270902070206ff00"
            + "00004a";

        // The data that the subkey binding signature of RFC 9580 A.3 is made over (A.3.1)
        private const string Rfc9580A3BindingHashedData =
            "a6e9186d9d5935fc8fe56314cdb527486a5a5120f9b762a235a729f039010a569b0000002a0663877fe31b00000020f94da7bb48"
            + "d60a61e567706a6587d0331999bb9d891a08242ead84543df895a39b0000002a0663877fe319000000208693248367f9e5015db9"
            + "22f8f48095dda784987f2d5985b12fbad16caf5e443506181b0a0000002c058263877fe3029b0c222106cb186c4f0609a697e4d5"
            + "2dfa6c722b0c1f1e27c18a56708f6525ec27bad9acc906ff00000034";

        private static readonly SecureRandom Random = new SecureRandom();

        private static PgpPublicKeyRing Rfc9580Certificate() =>
            new PgpPublicKeyRing(PgpV6TestUtilities.LoadRfc9580("a3-v6-certificate.asc"));

        private static PgpSignature DirectKeySignature(PgpPublicKey primary) =>
            primary.GetSignaturesOfType(PgpSignature.DirectKey).Single();

        private static PgpSignature ReparseWith(SignaturePacket packet) =>
            ((PgpSignatureList)new PgpObjectFactory(packet.GetEncoded()).NextPgpObject())[0];

        private static SignaturePacket PacketOf(PgpSignature signature) =>
            PgpV6TestUtilities.ReadPacket<SignaturePacket>(signature.GetEncoded());

        /// <summary>A copy of the packet with some parts replaced; the signature value is kept.</summary>
        private static SignaturePacket Rebuild(SignaturePacket p, HashAlgorithmTag? hash = null,
            byte[] salt = null, byte[] digestPrefix = null, SignatureSubpacket[] unhashed = null, int? type = null,
            byte[] signatureBytes = null)
        {
            return new SignaturePacket(p.Version, p.HasNewPacketFormat, type ?? p.SignatureType, p.KeyId,
                p.KeyAlgorithm, hash ?? p.HashAlgorithm, p.GetHashedSubPackets(), unhashed ?? p.GetUnhashedSubPackets(),
                digestPrefix ?? p.GetFingerprint(), salt ?? p.GetSalt(), null, signatureBytes ?? p.GetSignatureBytes());
        }

        // The self-signatures of RFC 9580 A.3 verify.
        [Test]
        public void Rfc9580SelfSignaturesVerify()
        {
            PgpPublicKeyRing ring = Rfc9580Certificate();
            PgpPublicKey primary = ring.GetPublicKey();
            PgpPublicKey subkey = ring.GetPublicKeys().Last();

            PgpSignature direct = DirectKeySignature(primary);
            Assert.That(direct.Version, Is.EqualTo(6));
            Assert.That(direct.GetSalt().Length, Is.EqualTo(32));
            direct.InitVerify(primary);
            Assert.That(direct.VerifyCertification(primary), Is.True);

            PgpSignature binding = subkey.GetSignaturesOfType(PgpSignature.SubkeyBinding).Single();
            binding.InitVerify(primary);
            Assert.That(binding.VerifyCertification(primary, subkey), Is.True);

            // the secret key version of the certificate has the same signatures
            var secretRing = new PgpSecretKeyRing(PgpV6TestUtilities.LoadRfc9580("a4-v6-secret-key.asc"));
            PgpPublicKey secretPrimary = secretRing.GetPublicKey();
            PgpSignature secretDirect = DirectKeySignature(secretPrimary);
            secretDirect.InitVerify(secretPrimary);
            Assert.That(secretDirect.VerifyCertification(secretPrimary), Is.True);
        }

        // The data that is hashed is the one of RFC 9580 A.3.1.
        [Test]
        public void HashedDataStreamMatchesRfc9580()
        {
            PgpPublicKeyRing ring = Rfc9580Certificate();
            PgpPublicKey primary = ring.GetPublicKey();
            PgpPublicKey subkey = ring.GetPublicKeys().Last();

            byte[] keyBody = primary.PublicKeyPacket.GetEncodedContents();
            byte[] subkeyBody = subkey.PublicKeyPacket.GetEncodedContents();
            byte[] KeyPacket(byte[] body) => Arrays.Concatenate(new byte[]{ 0x9B, 0, 0, 0, (byte)body.Length }, body);

            PgpSignature direct = DirectKeySignature(primary);
            byte[] directStream = Arrays.ConcatenateAll(direct.GetSalt(), KeyPacket(keyBody),
                direct.GetSignatureTrailer());
            Assert.That(Hex.ToHexString(directStream), Is.EqualTo(Rfc9580A3DirectKeyHashedData));

            PgpSignature binding = subkey.GetSignaturesOfType(PgpSignature.SubkeyBinding).Single();
            byte[] bindingStream = Arrays.ConcatenateAll(binding.GetSalt(), KeyPacket(keyBody), KeyPacket(subkeyBody),
                binding.GetSignatureTrailer());
            Assert.That(Hex.ToHexString(bindingStream), Is.EqualTo(Rfc9580A3BindingHashedData));

            // the first two octets of the digest of this data are the digest prefix of the signature
            byte[] digest = DigestUtilities.CalculateDigest("SHA-512", directStream);
            Assert.That(direct.GetDigestPrefix(), Is.EqualTo(Arrays.CopyOfRange(digest, 0, 2)));
            digest = DigestUtilities.CalculateDigest("SHA-512", bindingStream);
            Assert.That(binding.GetDigestPrefix(), Is.EqualTo(Arrays.CopyOfRange(digest, 0, 2)));
        }

        [Test]
        public void WrongDigestPrefixIsRejected()
        {
            PgpPublicKey primary = Rfc9580Certificate().GetPublicKey();
            SignaturePacket original = PacketOf(DirectKeySignature(primary));

            byte[] prefix = original.GetFingerprint();
            prefix[1] ^= 0x01;

            PgpSignature signature = ReparseWith(Rebuild(original, digestPrefix: prefix));
            signature.InitVerify(primary);
            Assert.That(signature.VerifyCertification(primary), Is.False);

            // while the unmodified one works
            PgpSignature intact = ReparseWith(Rebuild(original));
            intact.InitVerify(primary);
            Assert.That(intact.VerifyCertification(primary), Is.True);
        }

        [Test]
        public void SaltLengthMustMatchTheHashAlgorithm()
        {
            PgpPublicKey primary = Rfc9580Certificate().GetPublicKey();
            SignaturePacket original = PacketOf(DirectKeySignature(primary));

            foreach (int length in new[]{ 0, 16, 31, 33 })
            {
                PgpSignature signature = ReparseWith(Rebuild(original, salt: new byte[length]));
                signature.InitVerify(primary);
                Assert.That(signature.VerifyCertification(primary), Is.False, "salt length " + length);
            }

            // hashes that have no defined salt size cannot be used for version 6 signatures
            foreach (var hash in new[]{ HashAlgorithmTag.Sha1, HashAlgorithmTag.MD5, HashAlgorithmTag.RipeMD160 })
            {
                PgpSignature signature = ReparseWith(Rebuild(original, hash: hash, salt: new byte[20]));
                signature.InitVerify(primary);
                Assert.That(signature.VerifyCertification(primary), Is.False, hash.ToString());
            }
        }

        [Test]
        public void Version6SignatureIsNotValidForVersion4Key()
        {
            var v4Ring = PgpMLKemX25519Test.A2PublicRing();
            PgpPublicKey v4Primary = v4Ring.GetPublicKey();
            Assert.That(v4Primary.Version, Is.EqualTo(4));

            // the direct key signature of the version 6 key, checked against a version 4 key of the same algorithm
            PgpSignature v6Signature = DirectKeySignature(Rfc9580Certificate().GetPublicKey());
            v6Signature.InitVerify(v4Primary);
            Assert.That(v6Signature.VerifyCertification(v4Primary), Is.False);
        }

        [Test]
        public void Version4SignatureIsNotValidForVersion6Key()
        {
            var keyPair = new PgpKeyPair(PublicKeyAlgorithmTag.Ed25519,
                PgpEdDsaV4SignatureTest.GenerateKeyPair(PublicKeyAlgorithmTag.Ed25519), DateTime.UtcNow);
            var generator = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha256);
            generator.InitSign(PgpSignature.BinaryDocument, keyPair.PrivateKey);
            generator.Update(Strings.ToUtf8ByteArray("text"));
            PgpSignature v4Signature = generator.Generate();

            PgpPublicKey v6Key = Rfc9580Certificate().GetPublicKey();
            v4Signature.InitVerify(v6Key);
            v4Signature.Update(Strings.ToUtf8ByteArray("text"));
            Assert.That(v4Signature.Verify(), Is.False);

            // but it works with its own key
            v4Signature.InitVerify(keyPair.PublicKey);
            v4Signature.Update(Strings.ToUtf8ByteArray("text"));
            Assert.That(v4Signature.Verify(), Is.True);
        }

        [Test]
        public void WeakHashIsRejected()
        {
            PgpPublicKey primary = Rfc9580Certificate().GetPublicKey();
            SignaturePacket original = PacketOf(DirectKeySignature(primary));

            // SHA-224 has a salt size of 16 octets
            PgpSignature signature = ReparseWith(Rebuild(original, hash: HashAlgorithmTag.Sha224,
                salt: new byte[16]));
            signature.InitVerify(primary);
            Assert.That(signature.VerifyCertification(primary), Is.False);
        }

        [Test]
        public void IssuerKeyIdInVersion6SignatureIsTolerated()
        {
            PgpPublicKey primary = Rfc9580Certificate().GetPublicKey();
            SignaturePacket original = PacketOf(DirectKeySignature(primary));

            var unhashed = new SignatureSubpacket[]{ new IssuerKeyId(false, primary.KeyId) };
            PgpSignature signature = ReparseWith(Rebuild(original, unhashed: unhashed));

            Assert.That(signature.GetUnhashedSubPackets().HasSubpacket(SignatureSubpacketTag.IssuerKeyId), Is.True);
            signature.InitVerify(primary);
            Assert.That(signature.VerifyCertification(primary), Is.True);
        }

        [Test]
        public void IssuerFingerprintOfOtherVersionIsRejected()
        {
            PgpPublicKey primary = Rfc9580Certificate().GetPublicKey();
            SignaturePacket original = PacketOf(DirectKeySignature(primary));

            var unhashed = new SignatureSubpacket[]{ new IssuerFingerprint(false, 4, new byte[20]) };
            PgpSignature signature = ReparseWith(Rebuild(original, unhashed: unhashed));

            signature.InitVerify(primary);
            Assert.That(signature.VerifyCertification(primary), Is.False);
        }

        [Test]
        public void ReservedSignatureTypeIsRejected()
        {
            PgpPublicKey primary = Rfc9580Certificate().GetPublicKey();
            SignaturePacket original = PacketOf(DirectKeySignature(primary));

            PgpSignature signature = ReparseWith(Rebuild(original, type: 0xFF));
            signature.InitVerify(primary);
            signature.Update(Strings.ToUtf8ByteArray("data"));
            Assert.That(signature.Verify(), Is.False);
        }

        [Test]
        public void MalformedSignatureIsRejected()
        {
            PgpPublicKey primary = Rfc9580Certificate().GetPublicKey();
            SignaturePacket original = PacketOf(DirectKeySignature(primary));

            // one more octet than an Ed25519 signature has: parsed, but flagged as malformed
            byte[] encoding = Rebuild(original).GetEncoded();
            byte[] body = Arrays.Concatenate(Arrays.CopyOfRange(encoding, 2, encoding.Length), new byte[]{ 0 });
            byte[] longer = PgpV6TestUtilities.NewFormatPacket(PacketTag.Signature, body);

            PgpSignature signature = ((PgpSignatureList)new PgpObjectFactory(longer).NextPgpObject())[0];
            signature.InitVerify(primary);
            Assert.That(signature.VerifyCertification(primary), Is.False);
        }

        [Test]
        public void ModifiedSignatureValueIsRejected()
        {
            PgpPublicKey primary = Rfc9580Certificate().GetPublicKey();
            SignaturePacket original = PacketOf(DirectKeySignature(primary));

            byte[] value = original.GetSignatureBytes();
            value[10] ^= 0x01;

            PgpSignature signature = ReparseWith(Rebuild(original, signatureBytes: value));
            signature.InitVerify(primary);
            Assert.That(signature.VerifyCertification(primary), Is.False);
        }

        // The self-signatures of RFC 9980 A.1 (version 6) and A.2 (version 4) verify.
        [Test]
        public void Rfc9980SelfSignaturesVerify()
        {
            var a1 = new PgpPublicKeyRing(PgpV6TestUtilities.LoadRfc9980("a1-public-key.asc"));
            PgpPublicKey primary = a1.GetPublicKey();
            PgpPublicKey subkey = a1.GetPublicKeys().Last();
            Assert.That(primary.Version, Is.EqualTo(6));

            DirectKeySignature(primary).InitVerify(primary);
            PgpSignature direct = DirectKeySignature(primary);
            direct.InitVerify(primary);
            Assert.That(direct.VerifyCertification(primary), Is.True);
            Assert.That(direct.GetSalt().Length, Is.EqualTo(16));
            Assert.That(direct.HashAlgorithm, Is.EqualTo(HashAlgorithmTag.Sha256));

            string userId = primary.GetUserIds().First();
            PgpSignature certification = primary.GetSignaturesForId(userId).Single();
            certification.InitVerify(primary);
            Assert.That(certification.VerifyCertification(userId, primary), Is.True);

            PgpSignature binding = subkey.GetSignaturesOfType(PgpSignature.SubkeyBinding).Single();
            binding.InitVerify(primary);
            Assert.That(binding.VerifyCertification(primary, subkey), Is.True);

            // the bindings of A.2 (a version 4 certificate) as well
            var a2 = PgpMLKemX25519Test.A2PublicRing();
            PgpPublicKey a2Primary = a2.GetPublicKey();
            PgpSignature a2Binding = a2.GetPublicKeys().Last().GetSignaturesOfType(PgpSignature.SubkeyBinding).Single();
            a2Binding.InitVerify(a2Primary);
            Assert.That(a2Binding.VerifyCertification(a2Primary, a2.GetPublicKeys().Last()), Is.True);
        }
    }
}
