using System;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    /// <summary>
    /// A parsed public key packet must remember its header format so that re-encoding round-trips the input.
    /// </summary>
    [TestFixture]
    public class PublicKeyPacketFormatTest
    {
        [Test]
        public void PrimaryKeyPacketKeepsHeaderFormat()
        {
            var packet = new PublicKeyPacket(PublicKeyPacket.Version4, PublicKeyAlgorithmTag.X25519,
                new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc), new X25519PublicBcpgKey(new byte[32]));

            foreach (var format in new[]{ PacketFormat.Current, PacketFormat.Legacy })
            {
                byte[] encoded = packet.GetEncoded(format);

                var parsed = (PublicKeyPacket)BcpgInputStream.Wrap(new MemoryStream(encoded, false)).ReadPacket();

                Assert.That(parsed.HasNewPacketFormat, Is.EqualTo(format == PacketFormat.Current));
                Assert.That(Arrays.AreEqual(encoded, parsed.GetEncoded()), Is.True);
            }
        }
    }
}
