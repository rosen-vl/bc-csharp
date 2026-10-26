using System.IO;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    /// <summary>Helpers shared by the RFC 9580 version 6 and RFC 9980 test fixtures.</summary>
    internal static class PgpV6TestUtilities
    {
        /// <summary>The message that all RFC 9980 detached signature vectors cover.</summary>
        internal static readonly byte[] Rfc9980Message = Strings.ToUtf8ByteArray("Testing\n");

        /// <summary>Armored RFC 9580 Appendix A vector files that consist of keys and signatures only.</summary>
        internal static readonly string[] Rfc9580KeyAndSignatureFiles =
        {
            "a2-v4-ed25519legacy-signature.asc",
            "a3-v6-certificate.asc",
            "a4-v6-secret-key.asc",
            "a5-v6-locked-secret-key.asc",
        };

        /// <summary>Armored RFC 9980 Appendix A vector files that consist of keys and signatures only.</summary>
        internal static readonly string[] Rfc9980KeyAndSignatureFiles =
        {
            "a1-public-key.asc", "a1-secret-key.asc",
            "a3-public-key.asc", "a3-secret-key.asc", "a3-signature.asc",
            "a4-public-key.asc", "a4-secret-key.asc", "a4-signature.asc",
            "a5-public-key.asc", "a5-secret-key.asc", "a5-signature.asc",
            "a6-public-key.asc", "a6-secret-key.asc", "a6-signature.asc",
            "a7-public-key.asc", "a7-secret-key.asc", "a7-signature.asc",
        };

        internal static byte[] LoadRfc9580(string name) => LoadVector("rfc9580", name);

        internal static byte[] LoadRfc9980(string name) => LoadVector("rfc9980", name);

        /// <summary>Load an armored test vector from <c>data/openpgp/&lt;directory&gt;</c> and de-armor it.</summary>
        internal static byte[] LoadVector(string directory, string name)
        {
            using (var armored = new ArmoredInputStream(
                SimpleTest.GetTestDataAsStream("openpgp." + directory + "." + name)))
            {
                return Streams.ReadAll(armored);
            }
        }

        /// <summary>Encode a packet with a new-format header and a definite length.</summary>
        internal static byte[] NewFormatPacket(PacketTag tag, byte[] body)
        {
            var bOut = new MemoryStream();
            bOut.WriteByte((byte)(0xC0 | (int)tag));
            if (body.Length < 192)
            {
                bOut.WriteByte((byte)body.Length);
            }
            else if (body.Length < 8384)
            {
                int len = body.Length - 192;
                bOut.WriteByte((byte)((len >> 8) + 192));
                bOut.WriteByte((byte)len);
            }
            else
            {
                bOut.WriteByte(0xFF);
                bOut.WriteByte((byte)(body.Length >> 24));
                bOut.WriteByte((byte)(body.Length >> 16));
                bOut.WriteByte((byte)(body.Length >> 8));
                bOut.WriteByte((byte)body.Length);
            }
            bOut.Write(body, 0, body.Length);
            return bOut.ToArray();
        }

        /// <summary>The packet tag of a packet with an old- or new-format header.</summary>
        internal static int PacketTagOf(byte[] packet) =>
            (packet[0] & 0x40) != 0 ? packet[0] & 0x3F : (packet[0] >> 2) & 0x0F;

        internal static T ReadPacket<T>(byte[] encoding)
            where T : Packet
        {
            return (T)BcpgInputStream.Wrap(new MemoryStream(encoding, false)).ReadPacket();
        }
    }
}
