using System;
using System.IO;
using System.Linq;

using NUnit.Framework;

using Org.BouncyCastle.Bcpg.Sig;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    /// <summary>Tests for version 6 signature packets (RFC 9580 5.2.3) and the RFC 9980 signature encodings.</summary>
    [TestFixture]
    public class PgpV6SignaturePacketTest
    {
        // The hashed trailer of the RFC 9580 A.3 direct key signature (the "trailer begins" part of A.3.1)
        private const string Rfc9580A3DirectKeyTrailer =
            "061f1b0a00000042058263877fe3030b090705150a0e080c021600029b03021e09222106cb186c4f0609a697e4d52dfa6c72"
            + "2b0c1f1e27c18a56708f6525ec27bad9acc905270902070206ff0000004a";

        private const string Rfc9580A3DirectKeySalt = "103e2d7d227ec0e6d7ce4471db36bfc9708325369027149"
            + "8a7ef0576c07faae1";

        private static readonly PublicKeyAlgorithmTag[] RawSignatureAlgorithms =
        {
            PublicKeyAlgorithmTag.Ed25519,
            PublicKeyAlgorithmTag.Ed448,
            PublicKeyAlgorithmTag.MLDsa65_Ed25519,
            PublicKeyAlgorithmTag.MLDsa87_Ed448,
            PublicKeyAlgorithmTag.SlhDsa_Shake128s,
            PublicKeyAlgorithmTag.SlhDsa_Shake128f,
            PublicKeyAlgorithmTag.SlhDsa_Shake256s,
        };

        private static int RawSignatureLength(PublicKeyAlgorithmTag algorithm)
        {
            switch (algorithm)
            {
            case PublicKeyAlgorithmTag.Ed25519: return 64;
            case PublicKeyAlgorithmTag.Ed448: return 114;
            case PublicKeyAlgorithmTag.MLDsa65_Ed25519: return 3373;
            case PublicKeyAlgorithmTag.MLDsa87_Ed448: return 4741;
            case PublicKeyAlgorithmTag.SlhDsa_Shake128s: return 7856;
            case PublicKeyAlgorithmTag.SlhDsa_Shake128f: return 17088;
            case PublicKeyAlgorithmTag.SlhDsa_Shake256s: return 29792;
            default: throw new ArgumentException();
            }
        }

        /// <summary>Build the body of a signature packet with empty subpacket areas.</summary>
        private static byte[] SignatureBody(byte version, PublicKeyAlgorithmTag algorithm, int saltLength,
            int signatureLength)
        {
            var body = new MemoryStream();
            body.WriteByte(version);
            body.WriteByte(0x00); // binary document
            body.WriteByte((byte)algorithm);
            body.WriteByte((byte)HashAlgorithmTag.Sha256);
            if (version == 6)
            {
                body.Write(new byte[8], 0, 8);
            }
            else
            {
                body.Write(new byte[4], 0, 4);
            }
            body.Write(new byte[]{ 0x12, 0x34 }, 0, 2);
            if (version == 6)
            {
                body.WriteByte((byte)saltLength);
                body.Write(new byte[saltLength], 0, saltLength);
            }
            for (int i = 0; i < signatureLength; ++i)
            {
                body.WriteByte((byte)(i * 31 + 7));
            }
            return body.ToArray();
        }

        private static byte[] SignaturePacketEncoding(byte[] body) =>
            PgpV6TestUtilities.NewFormatPacket(PacketTag.Signature, body);

        private static SignaturePacket ParseSignature(byte[] body) =>
            PgpV6TestUtilities.ReadPacket<SignaturePacket>(SignaturePacketEncoding(body));

        private static SignaturePacket RfcA3DirectKeySignature()
        {
            byte[] cert = PgpV6TestUtilities.LoadRfc9580("a3-v6-certificate.asc");
            return PgpV6TestUtilities.ReadPacket<SignaturePacket>(PgpUnsupportedVersionTest.SplitPackets(cert)[1]);
        }

        [Test]
        public void V6SignaturesReencodeByteExact()
        {
            int v6Count = 0;

            var files = PgpV6TestUtilities.Rfc9580KeyAndSignatureFiles
                .Select(f => PgpV6TestUtilities.LoadRfc9580(f))
                .Concat(PgpV6TestUtilities.Rfc9980KeyAndSignatureFiles.Select(f => PgpV6TestUtilities.LoadRfc9980(f)));

            foreach (byte[] data in files)
            {
                foreach (byte[] packet in PgpUnsupportedVersionTest.SplitPackets(data))
                {
                    if (PgpV6TestUtilities.PacketTagOf(packet) != (int)PacketTag.Signature)
                        continue;

                    var sigPacket = PgpV6TestUtilities.ReadPacket<SignaturePacket>(packet);
                    if (sigPacket.Version != 6)
                        continue;

                    ++v6Count;
                    Assert.That(sigPacket.IsMalformed, Is.False);
                    Assert.That(Arrays.AreEqual(packet, sigPacket.GetEncoded()), Is.True,
                        "re-encoding of a v6 signature with algorithm " + sigPacket.KeyAlgorithm);
                }
            }

            Assert.That(v6Count, Is.GreaterThan(40));
        }

        [Test]
        public void V6SubpacketAreasLargerThan64KiBUseLongLengths()
        {
            var hashed = new SignatureSubpacket[]
            {
                new SignatureCreationTime(true, DateTime.UtcNow),
                new PolicyUrl(false, true, new byte[70000]),
            };
            var unhashed = new SignatureSubpacket[]
            {
                new PolicyUrl(false, true, new byte[66000]),
            };

            var packet = new SignaturePacket(6, newPacketFormat: true, PgpSignature.BinaryDocument, 0,
                PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha512, hashed, unhashed, new byte[]{ 1, 2 },
                new byte[32], signature: null, signatureEncoding: new byte[64]);

            byte[] encoding = packet.GetEncoded();
            var parsed = PgpV6TestUtilities.ReadPacket<SignaturePacket>(encoding);

            Assert.That(parsed.Version, Is.EqualTo(6));
            Assert.That(parsed.GetHashedSubPackets().Length, Is.EqualTo(2));
            Assert.That(parsed.GetHashedSubPackets()[1].GetData().Length, Is.EqualTo(70000));
            Assert.That(parsed.GetUnhashedSubPackets()[0].GetData().Length, Is.EqualTo(66000));
            Assert.That(Arrays.AreEqual(encoding, parsed.GetEncoded()), Is.True);
        }

        [Test]
        public void SignatureTrailerMatchesRfc9580HashedDataStream()
        {
            SignaturePacket sig = RfcA3DirectKeySignature();

            Assert.That(sig.Version, Is.EqualTo(6));
            Assert.That(Hex.ToHexString(sig.GetSignatureTrailer()), Is.EqualTo(Rfc9580A3DirectKeyTrailer));
        }

        [Test]
        public void SaltIsReadAndReturnedAsCopy()
        {
            SignaturePacket sig = RfcA3DirectKeySignature();

            byte[] salt = sig.GetSalt();
            Assert.That(Hex.ToHexString(salt), Is.EqualTo(Rfc9580A3DirectKeySalt));

            salt[0] ^= 0xFF;
            Assert.That(Hex.ToHexString(sig.GetSalt()), Is.EqualTo(Rfc9580A3DirectKeySalt));
        }

        [Test]
        public void ConstructorValidatesSaltAndSignatureForm()
        {
            var hashed = new SignatureSubpacket[]{ new SignatureCreationTime(true, DateTime.UtcNow) };
            var unhashed = new SignatureSubpacket[0];
            byte[] prefix = new byte[2];

            SignaturePacket Create(int version, byte[] salt, MPInteger[] mpis, byte[] raw) => new SignaturePacket(
                version, false, PgpSignature.BinaryDocument, 1, PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha512,
                hashed, unhashed, prefix, salt, mpis, raw);

            // a valid version 6 packet and a valid version 4 packet
            Assert.That(Create(6, new byte[32], null, new byte[64]).Version, Is.EqualTo(6));
            Assert.That(Create(4, null, null, new byte[64]).Version, Is.EqualTo(4));

            // version 6 without a salt, version 4 with a salt
            Assert.Throws<ArgumentException>(() => Create(6, null, null, new byte[64]));
            Assert.Throws<ArgumentException>(() => Create(4, new byte[16], null, new byte[64]));

            // neither or both signature forms
            Assert.Throws<ArgumentException>(() => Create(6, new byte[32], null, null));
            Assert.Throws<ArgumentException>(() => Create(6, new byte[32],
                new[]{ new MPInteger(Org.BouncyCastle.Math.BigInteger.One) }, new byte[64]));
        }

        [Test]
        public void FixedSignatureLengthsAreEnforced()
        {
            foreach (var algorithm in RawSignatureAlgorithms)
            {
                int length = RawSignatureLength(algorithm);

                // exact length
                var exact = ParseSignature(SignatureBody(6, algorithm, 16, length));
                Assert.That(exact.IsMalformed, Is.False, algorithm.ToString());
                Assert.That(exact.GetSignatureBytes().Length, Is.EqualTo(length));
                Assert.That(exact.GetSalt().Length, Is.EqualTo(16));

                // one octet too many: parsed, but flagged
                var excess = ParseSignature(SignatureBody(6, algorithm, 16, length + 1));
                Assert.That(excess.IsMalformed, Is.True, algorithm.ToString());

                // one octet too few: a malformed packet
                Assert.Catch<IOException>(() => ParseSignature(SignatureBody(6, algorithm, 16, length - 1)),
                    algorithm.ToString());
            }
        }

        [Test]
        public void IssuerFingerprintWithOtherVersionIsFlagged()
        {
            byte[] fingerprint = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();
            byte[] fingerprintV4 = Enumerable.Range(101, 20).Select(i => (byte)i).ToArray();

            SignaturePacket Create(int version, int fingerprintVersion)
            {
                var hashed = new SignatureSubpacket[]
                {
                    new SignatureCreationTime(true, DateTime.UtcNow),
                    new IssuerFingerprint(false, fingerprintVersion, fingerprintVersion == 4 ? fingerprintV4 : fingerprint),
                };
                var packet = new SignaturePacket(version, false, PgpSignature.BinaryDocument, 0,
                    PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha512, hashed, new SignatureSubpacket[0],
                    new byte[2], version == 6 ? new byte[32] : null, null, new byte[64]);

                return PgpV6TestUtilities.ReadPacket<SignaturePacket>(packet.GetEncoded());
            }

            var matching = Create(6, 6);
            Assert.That(matching.IssuerFingerprintVersionMismatch, Is.False);

            var mismatching = Create(6, 4);
            Assert.That(mismatching.IssuerFingerprintVersionMismatch, Is.True);

            // the key ID is still derived from the fingerprint
            Assert.That(matching.KeyId, Is.EqualTo(0x0102030405060708L));
            Assert.That(mismatching.KeyId, Is.EqualTo(0x7172737475767778L));
        }

        [Test]
        public void V4SignatureWithPostQuantumAlgorithmParsesAsRawValue()
        {
            var sig = ParseSignature(SignatureBody(4, PublicKeyAlgorithmTag.MLDsa65_Ed25519, 0, 3373));

            Assert.That(sig.Version, Is.EqualTo(4));
            Assert.That(sig.GetSalt(), Is.Null);
            Assert.That(sig.GetSignature(), Is.Null);
            Assert.That(sig.GetSignatureBytes().Length, Is.EqualTo(3373));
        }

        [Test]
        public void JoinKeepsSaltAndRawSignatureEncoding()
        {
            byte[] cert = PgpV6TestUtilities.LoadRfc9580("a3-v6-certificate.asc");
            var sigPacket = PgpUnsupportedVersionTest.SplitPackets(cert)[1];

            var sig1 = new PgpSignature(PgpV6TestUtilities.ReadPacket<SignaturePacket>(sigPacket));
            var sig2 = new PgpSignature(PgpV6TestUtilities.ReadPacket<SignaturePacket>(sigPacket));

            PgpSignature joined = PgpSignature.Join(sig1, sig2);

            Assert.That(joined.Version, Is.EqualTo(6));
            Assert.That(Hex.ToHexString(joined.GetSalt()), Is.EqualTo(Rfc9580A3DirectKeySalt));
            Assert.That(Arrays.AreEqual(sigPacket, joined.GetEncoded()), Is.True);
        }

        [Test]
        public void OldFormatHeaderIsKept()
        {
            byte[] body = SignatureBody(6, PublicKeyAlgorithmTag.Ed25519, 16, 64);

            // old-format header: tag 2, one-octet length
            byte[] encoding = Arrays.Concatenate(new byte[]{ 0x88, (byte)body.Length }, body);

            var sig = PgpV6TestUtilities.ReadPacket<SignaturePacket>(encoding);

            Assert.That(sig.HasNewPacketFormat, Is.False);
            Assert.That(Arrays.AreEqual(encoding, sig.GetEncoded()), Is.True);
        }
    }
}
