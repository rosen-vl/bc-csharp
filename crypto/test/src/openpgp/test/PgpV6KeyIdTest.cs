using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    [TestFixture]
    public class PgpV6KeyIdTest
    {
        // First packet (public key, version 6) of the RFC 9580 A.3 certificate
        private const string Rfc9580A3PrimaryPacket =
            "c62a0663877fe31b00000020f94da7bb48d60a61e567706a6587d0331999bb9d891a08242ead84543df895a3";

        // First packet (public key, version 6) of the RFC 9980 A.1 certificate
        private const string Rfc9980A1PrimaryPacket =
            "c62a06677485801b00000020dcb4935cc4c860f8deff728e438f34731b29d6dd3fd70dbaf3b07cbaa5130afc";

        private static PgpPublicKey ParsePublicKey(string packetHex)
        {
            var bcpgIn = BcpgInputStream.Wrap(new MemoryStream(Hex.Decode(packetHex), false));
            return new PgpPublicKey((PublicKeyPacket)bcpgIn.ReadPacket());
        }

        [Test]
        public void V6KeyIdIsLeftmostFingerprintOctets()
        {
            var key = ParsePublicKey(Rfc9580A3PrimaryPacket);

            Assert.That(key.Version, Is.EqualTo(6));
            Assert.That(Hex.ToHexString(key.GetFingerprint()),
                Is.EqualTo("cb186c4f0609a697e4d52dfa6c722b0c1f1e27c18a56708f6525ec27bad9acc9"));
            Assert.That(key.KeyId, Is.EqualTo(unchecked((long)0xcb186c4f0609a697UL)));
        }

        [Test]
        public void V6KeyIdIsLeftmostFingerprintOctetsRfc9980()
        {
            var key = ParsePublicKey(Rfc9980A1PrimaryPacket);

            Assert.That(Hex.ToHexString(key.GetFingerprint()),
                Is.EqualTo("c789e17d9dbdca7b3c833a3c063feb0353f80ad911fe27868fb0645df803e947"));
            Assert.That(key.KeyId, Is.EqualTo(unchecked((long)0xc789e17d9dbdca7bUL)));
        }

        [Test]
        public void V4KeyIdIsStillRightmostFingerprintOctets()
        {
            // RFC 9980 A.2 v4 certificate
            var key = PgpMLKemX25519Test.A2PublicRing().GetPublicKey();

            Assert.That(Hex.ToHexString(key.GetFingerprint()),
                Is.EqualTo("342e5db2de345215cb2c944f7102ffed3b9cf12d"));
            Assert.That(key.KeyId, Is.EqualTo(unchecked((long)0x7102ffed3b9cf12dUL)));
        }
    }
}
