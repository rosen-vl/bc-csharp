using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    /// <summary>
    /// RFC 9580 3.2: in version 6 key, signature and PKESK packets, an MPI whose encoded length does not match the
    /// length starting at its most significant non-zero bit makes the packet malformed. Older packet versions stay
    /// lenient.
    /// </summary>
    [TestFixture]
    public class PgpV6MpiTest
    {
        // 0x01FF is 9 bits long
        private static readonly byte[] MinimalMpi = { 0x00, 0x09, 0x01, 0xFF };

        // an extra leading zero octet: 17 bits are declared for a 9-bit value
        private static readonly byte[] LeadingZeroMpi = { 0x00, 0x11, 0x00, 0x01, 0xFF };

        // the bit count is one too large for the value
        private static readonly byte[] LongBitCountMpi = { 0x00, 0x0A, 0x01, 0xFF };

        private static readonly byte[] Exponent = { 0x00, 0x02, 0x03 };

        private static readonly byte[][] NonMinimalMpis = { LeadingZeroMpi, LongBitCountMpi };

        private static byte[] RsaPublicKeyBody(int version, byte[] modulus)
        {
            byte[] material = Arrays.Concatenate(modulus, Exponent);

            var body = new MemoryStream();
            body.Write(new byte[]{ (byte)version, 0x63, 0x87, 0x7f, 0xe3, (byte)PublicKeyAlgorithmTag.RsaGeneral }, 0, 6);
            if (version == 6)
            {
                body.Write(new byte[]{ 0, 0, 0, (byte)material.Length }, 0, 4);
            }
            body.Write(material, 0, material.Length);
            return body.ToArray();
        }

        private static byte[] RsaSignatureBody(int version, byte[] value)
        {
            var body = new MemoryStream();
            body.Write(new byte[]{ (byte)version, 0x00, (byte)PublicKeyAlgorithmTag.RsaGeneral,
                (byte)HashAlgorithmTag.Sha256 }, 0, 4);
            body.Write(new byte[version == 6 ? 8 : 4], 0, version == 6 ? 8 : 4);
            body.Write(new byte[]{ 0x12, 0x34 }, 0, 2);
            if (version == 6)
            {
                body.WriteByte(16);
                body.Write(new byte[16], 0, 16);
            }
            body.Write(value, 0, value.Length);
            return body.ToArray();
        }

        private static byte[] RsaPkeskBody(int version, byte[] value)
        {
            var body = new MemoryStream();
            body.WriteByte((byte)version);
            if (version == 6)
            {
                body.WriteByte(0);  // anonymous
            }
            else
            {
                body.Write(new byte[8], 0, 8);
            }
            body.WriteByte((byte)PublicKeyAlgorithmTag.RsaGeneral);
            body.Write(value, 0, value.Length);
            return body.ToArray();
        }

        private static T Parse<T>(PacketTag tag, byte[] body)
            where T : Packet
        {
            return PgpV6TestUtilities.ReadPacket<T>(PgpV6TestUtilities.NewFormatPacket(tag, body));
        }

        [Test]
        public void NonMinimalMpiInVersion6KeyPacketIsMalformed()
        {
            Assert.That(Parse<PublicKeyPacket>(PacketTag.PublicKey, RsaPublicKeyBody(6, MinimalMpi)).Key,
                Is.InstanceOf<RsaPublicBcpgKey>());

            foreach (byte[] mpi in NonMinimalMpis)
            {
                Assert.Throws<MalformedPacketException>(
                    () => Parse<PublicKeyPacket>(PacketTag.PublicKey, RsaPublicKeyBody(6, mpi)));
                Assert.Throws<MalformedPacketException>(
                    () => Parse<PublicKeyPacket>(PacketTag.PublicSubkey, RsaPublicKeyBody(6, mpi)));

                // the same encoding in a version 4 packet is accepted
                var v4 = Parse<PublicKeyPacket>(PacketTag.PublicKey, RsaPublicKeyBody(4, mpi));
                Assert.That(((RsaPublicBcpgKey)v4.Key).Modulus.IntValue, Is.EqualTo(0x1FF));
            }
        }

        [Test]
        public void NonMinimalMpiInVersion6SignatureIsFlagged()
        {
            Assert.That(Parse<SignaturePacket>(PacketTag.Signature, RsaSignatureBody(6, MinimalMpi)).IsMalformed,
                Is.False);

            foreach (byte[] mpi in NonMinimalMpis)
            {
                // the packet still parses, so that it does not prevent the parsing of the surrounding data
                var v6 = Parse<SignaturePacket>(PacketTag.Signature, RsaSignatureBody(6, mpi));
                Assert.That(v6.IsMalformed, Is.True);

                var v4 = Parse<SignaturePacket>(PacketTag.Signature, RsaSignatureBody(4, mpi));
                Assert.That(v4.IsMalformed, Is.False);
            }
        }

        [Test]
        public void NonMinimalMpiInVersion6PkeskIsFlagged()
        {
            Assert.That(Parse<PublicKeyEncSessionPacket>(PacketTag.PublicKeyEncryptedSession,
                RsaPkeskBody(6, MinimalMpi)).IsMalformed, Is.False);

            foreach (byte[] mpi in NonMinimalMpis)
            {
                var v6 = Parse<PublicKeyEncSessionPacket>(PacketTag.PublicKeyEncryptedSession, RsaPkeskBody(6, mpi));
                Assert.That(v6.IsMalformed, Is.True);

                var v3 = Parse<PublicKeyEncSessionPacket>(PacketTag.PublicKeyEncryptedSession, RsaPkeskBody(3, mpi));
                Assert.That(v3.IsMalformed, Is.False);
            }
        }

        [Test]
        public void NonMinimalEcdhPointInVersion6PkeskIsFlagged()
        {
            byte[] Body(int version, byte[] pointMpi) => Arrays.ConcatenateAll(
                version == 6 ? new byte[]{ 6, 0, (byte)PublicKeyAlgorithmTag.ECDH }
                    : new byte[]{ 3, 0, 0, 0, 0, 0, 0, 0, 0, (byte)PublicKeyAlgorithmTag.ECDH },
                pointMpi, new byte[]{ 8 }, new byte[8]);

            // a 65-octet point (0x04 prefix) has 515 bits
            byte[] point = new byte[65];
            point[0] = 0x04;
            byte[] minimal = Arrays.Concatenate(new byte[]{ 0x02, 0x03 }, point);
            byte[] extraBit = Arrays.Concatenate(new byte[]{ 0x02, 0x04 }, point);
            byte[] leadingZero = Arrays.ConcatenateAll(new byte[]{ 0x02, 0x0B, 0x00 }, point);

            Assert.That(Parse<PublicKeyEncSessionPacket>(PacketTag.PublicKeyEncryptedSession, Body(6, minimal))
                .IsMalformed, Is.False);
            Assert.That(Parse<PublicKeyEncSessionPacket>(PacketTag.PublicKeyEncryptedSession, Body(6, extraBit))
                .IsMalformed, Is.True);
            Assert.That(Parse<PublicKeyEncSessionPacket>(PacketTag.PublicKeyEncryptedSession, Body(6, leadingZero))
                .IsMalformed, Is.True);
            Assert.That(Parse<PublicKeyEncSessionPacket>(PacketTag.PublicKeyEncryptedSession, Body(3, extraBit))
                .IsMalformed, Is.False);
        }
    }
}
