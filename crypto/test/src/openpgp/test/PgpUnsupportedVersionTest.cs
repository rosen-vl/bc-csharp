using System;
using System.IO;
using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    /// <summary>
    /// Packets of versions this implementation does not support (e.g. RFC 9580 v6 one-pass signatures) must be
    /// skipped cleanly instead of being misparsed or aborting the surrounding message.
    /// </summary>
    [TestFixture]
    public class PgpUnsupportedVersionTest
    {
        private static readonly SecureRandom Random = new SecureRandom();

        /// <summary>Encode a packet with a new-format header (bodies up to 8383 octets).</summary>
        internal static byte[] NewFormatPacket(PacketTag tag, byte[] body)
        {
            var bOut = new MemoryStream();
            bOut.WriteByte((byte)(0xC0 | (int)tag));
            if (body.Length < 192)
            {
                bOut.WriteByte((byte)body.Length);
            }
            else
            {
                int len = body.Length - 192;
                bOut.WriteByte((byte)((len >> 8) + 192));
                bOut.WriteByte((byte)len);
            }
            bOut.Write(body, 0, body.Length);
            return bOut.ToArray();
        }

        internal static PgpSecretKeyRing GenerateRsaRing(out PgpPublicKeyRing publicRing)
        {
            var rsaGen = new RsaKeyPairGenerator();
            rsaGen.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(0x10001), Random, 2048, 100));
            var keyPair = new PgpKeyPair(PublicKeyAlgorithmTag.RsaGeneral, rsaGen.GenerateKeyPair(), DateTime.UtcNow);

            var krg = new PgpKeyRingGenerator(PgpSignature.PositiveCertification, keyPair, "rsa",
                SymmetricKeyAlgorithmTag.Null, HashAlgorithmTag.Sha256, new char[0], false, null, null, Random);
            publicRing = krg.GeneratePublicKeyRing();
            return krg.GenerateSecretKeyRing();
        }

        internal static byte[] EncryptTo(PgpPublicKey key, byte[] content)
        {
            var bOut = new MemoryStream();
            var encGen = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, true, Random);
            encGen.AddMethod(key);
            using (var encOut = encGen.Open(bOut, new byte[1 << 10]))
            using (var litOut = new PgpLiteralDataGenerator().Open(encOut, PgpLiteralData.Binary, "", content.Length,
                DateTime.UtcNow))
            {
                litOut.Write(content, 0, content.Length);
            }
            return bOut.ToArray();
        }

        [Test]
        public void UnusablePkeskPacketsDoNotBlockOtherRecipients()
        {
            PgpSecretKeyRing secretRing = GenerateRsaRing(out PgpPublicKeyRing publicRing);
            byte[] content = Encoding.ASCII.GetBytes("for the RSA recipient");
            byte[] message = EncryptTo(publicRing.GetPublicKey(), content);

            // v3 PKESK for a native X25519 key (RFC 9580 algorithm 25), which this implementation cannot decrypt
            byte[] x25519Body = new byte[1 + 8 + 1 + 32 + 1 + 1 + 24];
            x25519Body[0] = 3;
            x25519Body[9] = (byte)PublicKeyAlgorithmTag.X25519;
            x25519Body[42] = 25;
            x25519Body[43] = (byte)SymmetricKeyAlgorithmTag.Aes256;

            // PKESK of an unsupported version
            byte[] v6Body = new byte[1 + 1 + 1 + 20 + 1 + 40];
            v6Body[0] = 7;
            v6Body[1] = 21;
            v6Body[2] = 4;
            v6Body[23] = (byte)PublicKeyAlgorithmTag.X25519;

            byte[] combined = Arrays.ConcatenateAll(
                NewFormatPacket(PacketTag.PublicKeyEncryptedSession, v6Body),
                NewFormatPacket(PacketTag.PublicKeyEncryptedSession, x25519Body),
                message);

            var encList = (PgpEncryptedDataList)new PgpObjectFactory(combined).NextPgpObject();
            Assert.That(encList.Count, Is.EqualTo(2));

            var unusable = (PgpPublicKeyEncryptedData)encList[0];
            var rsaData = (PgpPublicKeyEncryptedData)encList[1];
            Assert.That(rsaData.KeyId, Is.EqualTo(publicRing.GetPublicKey().KeyId));

            PgpPrivateKey privateKey = secretRing.GetSecretKey().ExtractPrivateKey(new char[0]);
            Assert.Throws<PgpException>(() => unusable.GetDataStream(privateKey));

            var literal = (PgpLiteralData)new PgpObjectFactory(rsaData.GetDataStream(privateKey)).NextPgpObject();
            Assert.That(Arrays.AreEqual(content, Streams.ReadAll(literal.GetDataStream())), Is.True);
            Assert.That(rsaData.Verify(), Is.True);
        }

        /// <summary>Split a sequence of packets with old- or new-format headers (no partial lengths).</summary>
        internal static byte[][] SplitPackets(byte[] data)
        {
            var packets = new System.Collections.Generic.List<byte[]>();
            int pos = 0;
            while (pos < data.Length)
            {
                int start = pos, header = data[pos++], length;
                if ((header & 0x40) != 0)
                {
                    int first = data[pos++];
                    if (first < 192)
                    {
                        length = first;
                    }
                    else if (first < 224)
                    {
                        length = ((first - 192) << 8) + data[pos++] + 192;
                    }
                    else if (first == 255)
                    {
                        length = (data[pos] << 24) | (data[pos + 1] << 16) | (data[pos + 2] << 8) | data[pos + 3];
                        pos += 4;
                    }
                    else
                    {
                        throw new NotSupportedException("partial length");
                    }
                }
                else
                {
                    switch (header & 3)
                    {
                    case 0: length = data[pos++]; break;
                    case 1: length = (data[pos] << 8) | data[pos + 1]; pos += 2; break;
                    case 2:
                        length = (data[pos] << 24) | (data[pos + 1] << 16) | (data[pos + 2] << 8) | data[pos + 3];
                        pos += 4;
                        break;
                    default: throw new NotSupportedException("indeterminate length");
                    }
                }
                pos += length;
                packets.Add(Arrays.CopyOfRange(data, start, pos));
            }
            return packets.ToArray();
        }

        [Test]
        public void SeipdV2AfterV3PkeskDiscarded()
        {
            PgpSecretKeyRing secretRing = GenerateRsaRing(out PgpPublicKeyRing publicRing);
            byte[] rsaPkesk = SplitPackets(EncryptTo(publicRing.GetPublicKey(), new byte[16]))[0];

            // A v2 SEIPD (AEAD) payload, taken from the RFC 9980 A.2.4 sample message
            byte[] a24;
            using (var armored = new ArmoredInputStream(
                SimpleTest.GetTestDataAsStream("openpgp.rfc9980.a2-seipdv2-message.asc")))
            {
                a24 = Streams.ReadAll(armored);
            }
            byte[] seipdV2 = SplitPackets(a24)[1];
            Assert.That(seipdV2[0] & 0x3F, Is.EqualTo((int)PacketTag.SymmetricEncryptedIntegrityProtected));

            // RFC 9580 10.3.2.1: the v3 PKESK does not align with the v2 SEIPD payload and is discarded
            var encList = (PgpEncryptedDataList)new PgpObjectFactory(Arrays.Concatenate(rsaPkesk, seipdV2))
                .NextPgpObject();

            Assert.That(encList.IsEmpty, Is.True);
        }

        [Test]
        public void UnsupportedOnePassSignatureVersionSkipped()
        {
            // OPS of an unsupported version: version, type, hash, key algorithm, salt, fingerprint, nested flag
            var opsBody = new MemoryStream();
            opsBody.Write(new byte[]{ 7, 0x00, (byte)HashAlgorithmTag.Sha512, 30, 32 }, 0, 5);
            opsBody.Write(new byte[32], 0, 32);
            byte[] fingerprint = new byte[32];
            Arrays.Fill(fingerprint, 0xAB);
            opsBody.Write(fingerprint, 0, fingerprint.Length);
            opsBody.WriteByte(1);

            byte[] content = Encoding.ASCII.GetBytes("signed by a v6 key");
            var litBody = new MemoryStream();
            litBody.Write(new byte[]{ (byte)'b', 0, 0, 0, 0, 0 }, 0, 6);
            litBody.Write(content, 0, content.Length);

            // signature of an unsupported version: version, type, key algorithm, hash, hashed/unhashed lengths, left16,
            // salt, signature
            var sigBody = new MemoryStream();
            sigBody.Write(new byte[]{ 7, 0x00, 30, (byte)HashAlgorithmTag.Sha512, 0, 0, 0, 0, 0, 0, 0, 0,
                0x12, 0x34, 16 }, 0, 15);
            sigBody.Write(new byte[16 + 80], 0, 16 + 80);

            byte[] message = Arrays.ConcatenateAll(
                NewFormatPacket(PacketTag.OnePassSignature, opsBody.ToArray()),
                NewFormatPacket(PacketTag.LiteralData, litBody.ToArray()),
                NewFormatPacket(PacketTag.Signature, sigBody.ToArray()));

            var factory = new PgpObjectFactory(message);

            var opsList = (PgpOnePassSignatureList)factory.NextPgpObject();
            Assert.That(opsList.Count, Is.EqualTo(0));
            Assert.That(opsList.UnsupportedCount, Is.EqualTo(1));

            var literal = (PgpLiteralData)factory.NextPgpObject();
            Assert.That(Arrays.AreEqual(content, Streams.ReadAll(literal.GetDataStream())), Is.True);

            var sigList = (PgpSignatureList)factory.NextPgpObject();
            Assert.That(sigList.Count, Is.EqualTo(0));
            Assert.That(sigList.UnsupportedCount, Is.EqualTo(1));

            Assert.That(factory.NextPgpObject(), Is.Null);
        }
    }
}
