using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    /// <summary>Tests for the parsing of the S2K parameters of secret key packets (RFC 9580 5.5.3).</summary>
    [TestFixture]
    public class PgpV6SecretKeyPacketTest
    {
        // Body of the version 6 Ed25519 public key packet of the RFC 9580 A.3 certificate (without the packet header)
        private static byte[] V6PublicKeyBody() =>
            Arrays.CopyOfRange(PgpUnsupportedVersionTest.SplitPackets(
                PgpV6TestUtilities.LoadRfc9580("a3-v6-certificate.asc"))[0], 2, 2 + 42);

        // A version 4 X25519 public key packet body
        private static byte[] V4PublicKeyBody()
        {
            var body = new MemoryStream();
            body.Write(new byte[]{ 4, 0x63, 0x87, 0x7f, 0xe3, (byte)PublicKeyAlgorithmTag.X25519 }, 0, 6);
            body.Write(new byte[32], 0, 32);
            return body.ToArray();
        }

        private static readonly byte[] IteratedS2k = { 3, (byte)HashAlgorithmTag.Sha256, 1, 2, 3, 4, 5, 6, 7, 8, 0x60 };

        private static readonly byte[] Argon2S2k =
            Arrays.Concatenate(new byte[]{ 4 }, Arrays.Concatenate(new byte[16], new byte[]{ 3, 4, 16 }));

        /// <summary>A version 6 secret key packet body with usage 254 (CFB with SHA-1 check).</summary>
        private static byte[] V6SecretKeyBody(byte[] s2k, int count)
        {
            var body = new MemoryStream();
            byte[] publicBody = V6PublicKeyBody();
            body.Write(publicBody, 0, publicBody.Length);
            body.WriteByte(SecretKeyPacket.UsageSha1);
            body.WriteByte((byte)count);
            body.WriteByte((byte)SymmetricKeyAlgorithmTag.Aes128);
            body.WriteByte((byte)s2k.Length);
            body.Write(s2k, 0, s2k.Length);
            body.Write(new byte[16], 0, 16);    // IV
            body.Write(new byte[32 + 20], 0, 32 + 20);
            return body.ToArray();
        }

        private static byte[] V4SecretKeyBody(byte[] s2k)
        {
            var body = new MemoryStream();
            byte[] publicBody = V4PublicKeyBody();
            body.Write(publicBody, 0, publicBody.Length);
            body.WriteByte(SecretKeyPacket.UsageSha1);
            body.WriteByte((byte)SymmetricKeyAlgorithmTag.Aes128);
            body.Write(s2k, 0, s2k.Length);
            body.Write(new byte[16], 0, 16);    // IV
            body.Write(new byte[32 + 20], 0, 32 + 20);
            return body.ToArray();
        }

        private static SecretKeyPacket Parse(byte[] body) => PgpV6TestUtilities.ReadPacket<SecretKeyPacket>(
            PgpV6TestUtilities.NewFormatPacket(PacketTag.SecretKey, body));

        [Test]
        public void V6SecretKeyWithWrongConditionalParameterCountIsMalformed()
        {
            int correct = 1 + 1 + IteratedS2k.Length + 16;

            Assert.That(Parse(V6SecretKeyBody(IteratedS2k, correct)).S2kUsage, Is.EqualTo(SecretKeyPacket.UsageSha1));

            Assert.Throws<MalformedPacketException>(() => Parse(V6SecretKeyBody(IteratedS2k, correct - 1)));
            Assert.Throws<MalformedPacketException>(() => Parse(V6SecretKeyBody(IteratedS2k, correct + 1)));
            Assert.Throws<MalformedPacketException>(() => Parse(V6SecretKeyBody(IteratedS2k, 0)));
        }

        [Test]
        public void V6SecretKeyWithCorrectCountParses()
        {
            var packet = Parse(V6SecretKeyBody(IteratedS2k, 1 + 1 + IteratedS2k.Length + 16));

            Assert.That(packet.S2kUsage, Is.EqualTo(SecretKeyPacket.UsageSha1));
            Assert.That(packet.EncAlgorithm, Is.EqualTo(SymmetricKeyAlgorithmTag.Aes128));
            Assert.That(packet.S2k.Type, Is.EqualTo(S2k.SaltedAndIterated));
            Assert.That(packet.GetIV().Length, Is.EqualTo(16));
            Assert.That(packet.GetSecretKeyData().Length, Is.EqualTo(32 + 20));
        }

        [Test]
        public void V6AeadProtectedSecretKeysFromRfc9580Parse()
        {
            // RFC 9580 A.5: AES-256 with OCB, Argon2
            var ring = new PgpSecretKeyRing(PgpV6TestUtilities.LoadRfc9580("a5-v6-locked-secret-key.asc"));

            foreach (PgpSecretKey key in ring.GetSecretKeys())
            {
                Assert.That(key.S2kUsage, Is.EqualTo(SecretKeyPacket.UsageAead));
                Assert.That(key.S2k.Type, Is.EqualTo(S2k.Argon2));
            }
        }

        [Test]
        public void V4SecretKeyWithArgon2AndUsage254IsParsedButNotUsable()
        {
            byte[] encoding = PgpV6TestUtilities.NewFormatPacket(PacketTag.SecretKey, V4SecretKeyBody(Argon2S2k));

            var ring = new PgpSecretKeyRing(encoding);
            PgpSecretKey key = ring.GetSecretKey();

            Assert.That(key.S2kUsage, Is.EqualTo(SecretKeyPacket.UsageSha1));
            Assert.That(key.S2k.Type, Is.EqualTo(S2k.Argon2));

            var e = Assert.Throws<PgpException>(() => key.ExtractPrivateKey("password".ToCharArray()));
            Assert.That(e.Message, Does.Contain("malformed"));
        }

        [Test]
        public void V6SecretKeyWithArgon2AndUsage254IsParsedButNotUsable()
        {
            byte[] encoding = PgpV6TestUtilities.NewFormatPacket(PacketTag.SecretKey,
                V6SecretKeyBody(Argon2S2k, 1 + 1 + Argon2S2k.Length + 16));

            var ring = new PgpSecretKeyRing(encoding);
            PgpSecretKey key = ring.GetSecretKey();

            Assert.That(key.S2k.Type, Is.EqualTo(S2k.Argon2));
            var e = Assert.Throws<PgpException>(() => key.ExtractPrivateKey("password".ToCharArray()));
            Assert.That(e.Message, Does.Contain("malformed"));
        }
    }
}
