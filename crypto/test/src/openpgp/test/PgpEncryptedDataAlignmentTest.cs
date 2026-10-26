using System;
using System.IO;
using System.Linq;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    /// <summary>
    /// RFC 9580 10.3.2.1: ESK packets whose version does not align with the version of the encrypted payload are
    /// discarded.
    /// </summary>
    [TestFixture]
    public class PgpEncryptedDataAlignmentTest
    {
        private static byte[] NewFormatPacket(PacketTag tag, byte[] body) =>
            PgpV6TestUtilities.NewFormatPacket(tag, body);

        // v3 PKESK for an RSA key, with an opaque session key
        private static byte[] V3Pkesk() => NewFormatPacket(PacketTag.PublicKeyEncryptedSession,
            Arrays.ConcatenateAll(new byte[]{ 3, 1, 2, 3, 4, 5, 6, 7, 8, (byte)PublicKeyAlgorithmTag.RsaGeneral },
                new byte[]{ 0x00, 0x09, 0x01, 0xFF }));

        // v6 PKESK to the key with the fingerprint 'dafe...' (RFC 9980 A.1.3)
        private static byte[] V6Pkesk() =>
            PgpUnsupportedVersionTest.SplitPackets(PgpV6TestUtilities.LoadRfc9980("a1-message.asc"))[0];

        private static byte[] V4Skesk() => NewFormatPacket(PacketTag.SymmetricKeyEncryptedSessionKey,
            new byte[]{ 4, (byte)SymmetricKeyAlgorithmTag.Aes128, 0, (byte)HashAlgorithmTag.Sha256 });

        // v6 SKESK (RFC 9580 A.10)
        private static byte[] V6Skesk() =>
            PgpUnsupportedVersionTest.SplitPackets(PgpV6TestUtilities.LoadRfc9580("a10-ocb-message.asc"))[0];

        // v5 SKESK (LibrePGP): sym, aead, S2K, IV, encrypted key, tag
        private static byte[] V5Skesk() => NewFormatPacket(PacketTag.SymmetricKeyEncryptedSessionKey,
            Arrays.ConcatenateAll(new byte[]{ 5, (byte)SymmetricKeyAlgorithmTag.Aes128, (byte)AeadAlgorithmTag.Ocb },
                new byte[]{ 0, (byte)HashAlgorithmTag.Sha256 }, new byte[15], new byte[16], new byte[16]));

        private static byte[] SeipdV1() => NewFormatPacket(PacketTag.SymmetricEncryptedIntegrityProtected,
            Arrays.Concatenate(new byte[]{ 1 }, new byte[60]));

        private static byte[] SeipdV2() =>
            PgpUnsupportedVersionTest.SplitPackets(PgpV6TestUtilities.LoadRfc9980("a1-message.asc"))[1];

        private static byte[] Sed() =>
            NewFormatPacket(PacketTag.SymmetricKeyEncrypted, new byte[60]);

        private static byte[] AeadData() => NewFormatPacket(PacketTag.AeadEncData,
            Arrays.Concatenate(new byte[]{ 1, (byte)SymmetricKeyAlgorithmTag.Aes128, (byte)AeadAlgorithmTag.Ocb, 6 },
                new byte[15 + 32]));

        private static PgpEncryptedDataList Parse(params byte[][] packets) =>
            (PgpEncryptedDataList)new PgpObjectFactory(Arrays.ConcatenateAll(packets)).NextPgpObject();

        [Test]
        public void V3PkeskBeforeSeipdV2IsDiscarded()
        {
            Assert.That(Parse(V3Pkesk(), SeipdV2()).IsEmpty, Is.True);
            Assert.That(Parse(V4Skesk(), SeipdV2()).IsEmpty, Is.True);
        }

        [Test]
        public void V6EskBeforeSeipdV1OrSedIsDiscarded()
        {
            Assert.That(Parse(V6Pkesk(), SeipdV1()).IsEmpty, Is.True);
            Assert.That(Parse(V6Skesk(), SeipdV1()).IsEmpty, Is.True);
            Assert.That(Parse(V6Pkesk(), Sed()).IsEmpty, Is.True);
            Assert.That(Parse(V6Skesk(), Sed()).IsEmpty, Is.True);
        }

        [Test]
        public void OnlyAlignedEskPacketsAreExposed()
        {
            var forV2 = Parse(V3Pkesk(), V6Pkesk(), V4Skesk(), V6Skesk(), SeipdV2());
            Assert.That(forV2.Count, Is.EqualTo(2));
            Assert.That(forV2[0], Is.InstanceOf<PgpPublicKeyEncryptedData>());
            Assert.That(((PgpPublicKeyEncryptedData)forV2[0]).KeyId, Is.EqualTo(unchecked((long)0xdafe0eebb2675ecfUL)));
            Assert.That(forV2[1], Is.InstanceOf<PgpPbeEncryptedData>());
            Assert.That(((PgpPbeEncryptedData)forV2[1]).Version, Is.EqualTo(6));

            foreach (byte[] payload in new[]{ SeipdV1(), Sed() })
            {
                var forV1 = Parse(V3Pkesk(), V6Pkesk(), V4Skesk(), V6Skesk(), payload);
                Assert.That(forV1.Count, Is.EqualTo(2));
                Assert.That(forV1[0], Is.InstanceOf<PgpPublicKeyEncryptedData>());
                Assert.That(((PgpPublicKeyEncryptedData)forV1[0]).KeyId, Is.EqualTo(0x0102030405060708L));
                Assert.That(forV1[1], Is.InstanceOf<PgpPbeEncryptedData>());
                Assert.That(((PgpPbeEncryptedData)forV1[1]).Version, Is.EqualTo(4));
            }
        }

        [Test]
        public void LibrePgpOcbPacketsKeepTheirEskPackets()
        {
            var list = Parse(V3Pkesk(), V6Pkesk(), V4Skesk(), V5Skesk(), V6Skesk(), AeadData());

            Assert.That(list.Count, Is.EqualTo(2));
            Assert.That(list[0], Is.InstanceOf<PgpPublicKeyEncryptedData>());
            Assert.That(((PgpPbeEncryptedData)list[1]).Version, Is.EqualTo(5));
        }

        /// <summary>
        /// LibrePGP OCB encrypted data is not decrypted: not as CFB data without integrity protection through its v3
        /// PKESK, and not through its v5 SKESK.
        /// </summary>
        [Test]
        public void LibrePgpOcbDataIsNotDecrypted()
        {
            var list = Parse(V3Pkesk(), V5Skesk(), AeadData());

            var generator = new RsaKeyPairGenerator();
            generator.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(0x10001), new SecureRandom(), 1024, 25));
            var pair = new PgpKeyPair(PublicKeyAlgorithmTag.RsaGeneral, generator.GenerateKeyPair(), DateTime.UtcNow);

            var e = Assert.Throws<PgpException>(
                () => ((PgpPublicKeyEncryptedData)list[0]).GetDataStream(pair.PrivateKey));
            Assert.That(e.Message, Does.Contain("LibrePGP"));
            Assert.Throws<PgpException>(() => ((PgpPbeEncryptedData)list[1]).GetDataStream("password".ToCharArray()));
        }

        [Test]
        public void PayloadOfUnknownVersionKeepsAllEskPackets()
        {
            byte[] seipdV3 = NewFormatPacket(PacketTag.SymmetricEncryptedIntegrityProtected,
                Arrays.Concatenate(new byte[]{ 3 }, new byte[60]));

            Assert.That(Parse(V3Pkesk(), V6Pkesk(), V4Skesk(), V6Skesk(), seipdV3).Count, Is.EqualTo(4));
        }
    }
}
