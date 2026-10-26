using System;
using System.IO;
using System.Linq;
using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    /// <summary>Tests for the parsing and encoding of the RFC 9580 version 6 packet formats.</summary>
    [TestFixture]
    public class PgpV6PacketTest
    {
        private static readonly SecureRandom Random = new SecureRandom();

        private static byte[] NewFormatPacket(PacketTag tag, byte[] body) =>
            PgpUnsupportedVersionTest.NewFormatPacket(tag, body);

        private static byte[] PaddingPacket() => new PgpPadding(32, Random).GetEncoded();

        /// <summary>Append a padding packet after every packet of the given encoding.</summary>
        private static byte[] PadAfterEachPacket(byte[] encoded) =>
            Arrays.ConcatenateAll(PgpUnsupportedVersionTest.SplitPackets(encoded)
                .SelectMany(p => new[]{ p, PaddingPacket() }).ToArray());

        /// <summary>Length of the first packet (new format, definite length) of the given encoding.</summary>
        private static int FirstPacketLength(byte[] data) =>
            PgpUnsupportedVersionTest.SplitPackets(Arrays.CopyOfRange(data, 0, EndOfFirstPacket(data)))[0].Length;

        private static int EndOfFirstPacket(byte[] data)
        {
            int first = data[1];
            if (first < 192)
                return 2 + first;
            if (first < 224)
                return 3 + ((first - 192) << 8) + data[2] + 192;
            throw new NotSupportedException();
        }

        [Test]
        public void V6OnePassSignatureRoundTrip()
        {
            // RFC 9580 A.7 inline-signed message: OPS, literal data, signature
            byte[] message = PgpV6TestUtilities.LoadRfc9580("a7-inline-signed.asc");
            byte[] opsEncoding = PgpUnsupportedVersionTest.SplitPackets(message)[0];

            var ops = PgpV6TestUtilities.ReadPacket<OnePassSignaturePacket>(opsEncoding);

            Assert.That(ops.Version, Is.EqualTo(6));
            Assert.That(ops.SignatureType, Is.EqualTo(PgpSignature.CanonicalTextDocument));
            Assert.That(ops.HashAlgorithm, Is.EqualTo(HashAlgorithmTag.Sha512));
            Assert.That(ops.KeyAlgorithm, Is.EqualTo(PublicKeyAlgorithmTag.Ed25519));
            Assert.That(ops.GetSalt().Length, Is.EqualTo(32));
            Assert.That(ops.GetFingerprint().Length, Is.EqualTo(32));
            Assert.That(ops.IsNested, Is.False);
            Assert.That(Arrays.AreEqual(opsEncoding, ops.GetEncoded()), Is.True);

            // the other constructor produces the same packet
            var created = new OnePassSignaturePacket(ops.SignatureType, ops.HashAlgorithm, ops.KeyAlgorithm,
                ops.GetSalt(), ops.GetFingerprint(), isNested: false);
            Assert.That(Arrays.AreEqual(ops.GetEncoded(), created.GetEncoded(PacketFormat.Current)), Is.True);

            // accessors return copies
            ops.GetSalt()[0] ^= 0xFF;
            ops.GetFingerprint()[0] ^= 0xFF;
            Assert.That(Arrays.AreEqual(opsEncoding, ops.GetEncoded()), Is.True);
        }

        [Test]
        public void V6OnePassSignatureKeyIdIsFingerprintPrefix()
        {
            byte[] message = PgpV6TestUtilities.LoadRfc9580("a7-inline-signed.asc");
            var ops = PgpV6TestUtilities.ReadPacket<OnePassSignaturePacket>(
                PgpUnsupportedVersionTest.SplitPackets(message)[0]);

            // the certificate of RFC 9580 A.3 has the fingerprint cb186c4f...acc9
            Assert.That(Hex.ToHexString(ops.GetFingerprint()),
                Is.EqualTo("cb186c4f0609a697e4d52dfa6c722b0c1f1e27c18a56708f6525ec27bad9acc9"));
            Assert.That(ops.KeyId, Is.EqualTo(unchecked((long)0xcb186c4f0609a697UL)));

            var objects = new PgpObjectFactory(message).NextPgpObject();
            var list = (PgpOnePassSignatureList)objects;
            Assert.That(list.Count, Is.EqualTo(1));
            Assert.That(list[0].KeyId, Is.EqualTo(ops.KeyId));
        }

        [Test]
        public void V6OnePassSignatureFingerprintLengthIsChecked()
        {
            byte[] salt = new byte[32];

            Assert.Throws<ArgumentException>(() => new OnePassSignaturePacket(0, HashAlgorithmTag.Sha512,
                PublicKeyAlgorithmTag.Ed25519, salt, new byte[20], isNested: false));
            Assert.Throws<ArgumentException>(() => new OnePassSignaturePacket(0, HashAlgorithmTag.Sha512,
                PublicKeyAlgorithmTag.Ed25519, salt, new byte[33], isNested: false));
            Assert.Throws<ArgumentNullException>(() => new OnePassSignaturePacket(0, HashAlgorithmTag.Sha512,
                PublicKeyAlgorithmTag.Ed25519, salt, null, isNested: false));
        }

        [Test]
        public void V6PkeskRoundTrip()
        {
            // RFC 9980 A.1.3: PKESK to a v6 key (32-octet fingerprint)
            byte[] a13 = PgpV6TestUtilities.LoadRfc9980("a1-message.asc");
            byte[] a13Pkesk = PgpUnsupportedVersionTest.SplitPackets(a13)[0];
            var v6Key = PgpV6TestUtilities.ReadPacket<PublicKeyEncSessionPacket>(a13Pkesk);

            Assert.That(v6Key.Version, Is.EqualTo(6));
            Assert.That(v6Key.KeyVersion, Is.EqualTo(6));
            Assert.That(v6Key.Algorithm, Is.EqualTo(PublicKeyAlgorithmTag.MLKem768_X25519));
            Assert.That(Hex.ToHexString(v6Key.GetKeyFingerprint()),
                Is.EqualTo("dafe0eebb2675ecfcdc20a23fe89ca5d12e83f527dfa354b6dcf662131a48b9d"));
            Assert.That(v6Key.KeyId, Is.EqualTo(unchecked((long)0xdafe0eebb2675ecfUL)));
            Assert.That(Arrays.AreEqual(a13Pkesk, v6Key.GetEncoded()), Is.True);

            // RFC 9980 A.2.4: PKESK to a v4 key (20-octet fingerprint)
            byte[] a24 = PgpMLKemX25519Test.LoadA2("a2-seipdv2-message.asc");
            byte[] a24Pkesk = PgpUnsupportedVersionTest.SplitPackets(a24)[0];
            var v4Key = PgpV6TestUtilities.ReadPacket<PublicKeyEncSessionPacket>(a24Pkesk);

            Assert.That(v4Key.Version, Is.EqualTo(6));
            Assert.That(v4Key.KeyVersion, Is.EqualTo(4));
            Assert.That(Hex.ToHexString(v4Key.GetKeyFingerprint()), Is.EqualTo("e51dbfea51936988b5428fffa4f95f985ed61a51"));
            Assert.That(v4Key.KeyId, Is.EqualTo(unchecked((long)0xa4f95f985ed61a51UL)));
            Assert.That(Arrays.AreEqual(a24Pkesk, v4Key.GetEncoded()), Is.True);

            // anonymous recipient
            var anonymous = PublicKeyEncSessionPacket.CreateV6Packet(0, null, v6Key.Algorithm,
                v6Key.GetEncSessionKey());
            byte[] anonymousEncoding = anonymous.GetEncoded(PacketFormat.Current);
            var parsed = PgpV6TestUtilities.ReadPacket<PublicKeyEncSessionPacket>(anonymousEncoding);

            Assert.That(parsed.KeyVersion, Is.EqualTo(0));
            Assert.That(parsed.GetKeyFingerprint(), Is.Null);
            Assert.That(parsed.KeyId, Is.EqualTo(0L));
            Assert.That(parsed.Algorithm, Is.EqualTo(v6Key.Algorithm));
            Assert.That(Arrays.AreEqual(anonymousEncoding, parsed.GetEncoded()), Is.True);
            Assert.That(anonymousEncoding[PacketHeaderLength(anonymousEncoding) + 1], Is.EqualTo(0));

            // the version 3 factory method
            var v3 = PublicKeyEncSessionPacket.CreateV3Packet(0x0102030405060708L, PublicKeyAlgorithmTag.RsaGeneral,
                new[]{ new byte[]{ 0, 8, 0xFF } });
            Assert.That(v3.Version, Is.EqualTo(3));
            Assert.That(v3.KeyVersion, Is.EqualTo(0));
            Assert.That(v3.GetKeyFingerprint(), Is.Null);
        }

        private static int PacketHeaderLength(byte[] encoding) =>
            (encoding[0] & 0x40) == 0 ? 1 + new[]{ 1, 2, 4, 0 }[encoding[0] & 3]
                : encoding[1] < 192 ? 2 : encoding[1] < 224 ? 3 : 6;

        private static byte[] V6PkeskBody(int keyVersion, int fingerprintLength)
        {
            var body = new MemoryStream();
            body.WriteByte(6);
            body.WriteByte((byte)(1 + fingerprintLength));
            body.WriteByte((byte)keyVersion);
            body.Write(new byte[fingerprintLength], 0, fingerprintLength);
            body.WriteByte((byte)PublicKeyAlgorithmTag.X25519);
            body.Write(new byte[40], 0, 40);
            return body.ToArray();
        }

        [Test]
        public void V6PkeskFingerprintLengthMustMatchKeyVersion()
        {
            byte[] Packet(int keyVersion, int fingerprintLength) => NewFormatPacket(
                PacketTag.PublicKeyEncryptedSession, V6PkeskBody(keyVersion, fingerprintLength));

            Assert.That(PgpV6TestUtilities.ReadPacket<PublicKeyEncSessionPacket>(Packet(4, 20)).KeyVersion,
                Is.EqualTo(4));
            Assert.That(PgpV6TestUtilities.ReadPacket<PublicKeyEncSessionPacket>(Packet(6, 32)).KeyVersion,
                Is.EqualTo(6));

            Assert.Throws<MalformedPacketException>(() => PgpV6TestUtilities.ReadPacket<PublicKeyEncSessionPacket>(
                Packet(4, 32)));
            Assert.Throws<MalformedPacketException>(() => PgpV6TestUtilities.ReadPacket<PublicKeyEncSessionPacket>(
                Packet(6, 20)));

            // a key version that is not known is kept, with a key ID of zero
            var unknown = PgpV6TestUtilities.ReadPacket<PublicKeyEncSessionPacket>(Packet(5, 32));
            Assert.That(unknown.KeyVersion, Is.EqualTo(5));
            Assert.That(unknown.GetKeyFingerprint().Length, Is.EqualTo(32));
            Assert.That(unknown.KeyId, Is.EqualTo(0L));
            Assert.That(Arrays.AreEqual(Packet(5, 32), unknown.GetEncoded()), Is.True);
        }

        [Test]
        public void PkeskOfOtherVersionsIsStillSkipped()
        {
            PgpSecretKeyRing secretRing = PgpUnsupportedVersionTest.GenerateRsaRing(out PgpPublicKeyRing publicRing);
            byte[] content = Encoding.ASCII.GetBytes("after unsupported PKESK versions");
            byte[] message = PgpUnsupportedVersionTest.EncryptTo(publicRing.GetPublicKey(), content);

            byte[] unsupported = Arrays.ConcatenateAll(
                NewFormatPacket(PacketTag.PublicKeyEncryptedSession, new byte[]{ 4, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 }),
                NewFormatPacket(PacketTag.PublicKeyEncryptedSession, new byte[]{ 5, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 }),
                NewFormatPacket(PacketTag.PublicKeyEncryptedSession, new byte[]{ 7, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 }));

            var encList = (PgpEncryptedDataList)new PgpObjectFactory(Arrays.Concatenate(unsupported, message))
                .NextPgpObject();
            Assert.That(encList.Count, Is.EqualTo(1));
            Assert.That(((PgpPublicKeyEncryptedData)encList[0]).KeyId, Is.EqualTo(publicRing.GetPublicKey().KeyId));
        }

        [Test]
        public void UnsupportedSkeskVersionIsDrainedAndIgnored()
        {
            PgpSecretKeyRing secretRing = PgpUnsupportedVersionTest.GenerateRsaRing(out PgpPublicKeyRing publicRing);
            byte[] content = Encoding.ASCII.GetBytes("after an unsupported SKESK");
            byte[] message = PgpUnsupportedVersionTest.EncryptTo(publicRing.GetPublicKey(), content);

            byte[] skeskBody = new byte[40];
            skeskBody[0] = 99;
            for (int i = 1; i < skeskBody.Length; ++i)
            {
                skeskBody[i] = (byte)(i * 7);
            }

            byte[] combined = Arrays.Concatenate(NewFormatPacket(PacketTag.SymmetricKeyEncryptedSessionKey, skeskBody),
                message);

            var encList = (PgpEncryptedDataList)new PgpObjectFactory(combined).NextPgpObject();
            Assert.That(encList.Count, Is.EqualTo(1));

            var encData = (PgpPublicKeyEncryptedData)encList[0];
            PgpPrivateKey privateKey = secretRing.GetSecretKey().ExtractPrivateKey(new char[0]);

            var literal = (PgpLiteralData)new PgpObjectFactory(encData.GetDataStream(privateKey)).NextPgpObject();
            Assert.That(Arrays.AreEqual(content, Streams.ReadAll(literal.GetDataStream())), Is.True);
            Assert.That(encData.Verify(), Is.True);
        }

        [Test]
        public void V6SkeskWithMismatchedIVLengthIsMalformed()
        {
            // iterated and salted S2K with SHA-256
            byte[] s2k = { 3, (byte)HashAlgorithmTag.Sha256, 1, 2, 3, 4, 5, 6, 7, 8, 0x60 };

            // OCB needs a 15-octet nonce; 12 are given
            byte[] iv = new byte[12];
            byte[] encKey = new byte[32];
            byte[] tag = new byte[16];

            var body = new MemoryStream();
            body.Write(new byte[]{ 6, (byte)(3 + s2k.Length + iv.Length), (byte)SymmetricKeyAlgorithmTag.Aes256,
                (byte)AeadAlgorithmTag.Ocb, (byte)s2k.Length }, 0, 5);
            body.Write(s2k, 0, s2k.Length);
            body.Write(iv, 0, iv.Length);
            body.Write(encKey, 0, encKey.Length);
            body.Write(tag, 0, tag.Length);

            byte[] packet = NewFormatPacket(PacketTag.SymmetricKeyEncryptedSessionKey, body.ToArray());

            var bcpgIn = BcpgInputStream.Wrap(new MemoryStream(packet, false));
            Assert.Throws<MalformedPacketException>(() => bcpgIn.ReadPacket());
        }

        private static int PacketTagOf(byte[] packet) =>
            (packet[0] & 0x40) != 0 ? packet[0] & 0x3F : (packet[0] >> 2) & 0x0F;

        /// <summary>Insert the given packets after the third packet (the user ID certification) of a ring.</summary>
        private static byte[] InsertAfterUserIdCertification(byte[] ringEncoding, params byte[][] extra)
        {
            byte[][] packets = PgpUnsupportedVersionTest.SplitPackets(ringEncoding);
            Assert.That(PacketTagOf(packets[2]), Is.EqualTo((int)PacketTag.Signature));
            return Arrays.ConcatenateAll(Arrays.ConcatenateAll(packets.Take(3).ToArray()),
                Arrays.ConcatenateAll(extra), Arrays.ConcatenateAll(packets.Skip(3).ToArray()));
        }

        private static byte[] SignaturePacketBody(byte version, byte pkAlgorithm)
        {
            // version, type (positive certification), key algorithm, hash, hashed length, unhashed length, prefix,
            // and an opaque signature value
            return new byte[]{ version, 0x13, pkAlgorithm, (byte)HashAlgorithmTag.Sha256, 0, 0, 0, 0, 0x12, 0x34,
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
        }

        private static void CheckRingStillLoads(byte version, byte pkAlgorithm, int expectedSignatureCount)
        {
            PgpUnsupportedVersionTest.GenerateRsaRing(out PgpPublicKeyRing publicRing);
            byte[] extra = NewFormatPacket(PacketTag.Signature, SignaturePacketBody(version, pkAlgorithm));
            byte[] modified = InsertAfterUserIdCertification(publicRing.GetEncoded(), extra);

            var ring = new PgpPublicKeyRing(modified);
            PgpPublicKey master = ring.GetPublicKey();
            string userId = master.GetUserIds().First();

            var signatures = master.GetSignaturesForId(userId).ToList();
            Assert.That(signatures.Count, Is.EqualTo(expectedSignatureCount));

            // the genuine certification still verifies
            var certification = signatures.First(s => s.KeyAlgorithm == PublicKeyAlgorithmTag.RsaGeneral
                && s.Version == 4 && s.SignatureType == PgpSignature.PositiveCertification
                && s.HashAlgorithm == HashAlgorithmTag.Sha256 && s.KeyId == master.KeyId);
            certification.InitVerify(master);
            Assert.That(certification.VerifyCertification(userId, master), Is.True);

            // no key was lost
            Assert.That(ring.GetPublicKeys().Count(), Is.EqualTo(publicRing.GetPublicKeys().Count()));
        }

        [Test]
        public void KeyRingWithVersion5SignatureStillLoads() => CheckRingStillLoads(5, 1, 1);

        [Test]
        public void KeyRingWithVersion99SignatureStillLoads() => CheckRingStillLoads(99, 1, 1);

        [Test]
        public void KeyRingWithUnknownAlgorithmSignatureStillLoads()
        {
            CheckRingStillLoads(4, 99, 2);

            // the unknown-algorithm signature is kept but never verifies
            PgpUnsupportedVersionTest.GenerateRsaRing(out PgpPublicKeyRing publicRing);
            byte[] extra = NewFormatPacket(PacketTag.Signature, SignaturePacketBody(4, 99));
            var ring = new PgpPublicKeyRing(InsertAfterUserIdCertification(publicRing.GetEncoded(), extra));
            PgpPublicKey master = ring.GetPublicKey();
            string userId = master.GetUserIds().First();
            var unknown = master.GetSignaturesForId(userId).Single(s => (int)s.KeyAlgorithm == 99);

            unknown.InitVerify(master);
            Assert.That(unknown.VerifyCertification(userId, master), Is.False);
        }

        private static byte[] V4SubkeyBody(byte algorithm, int keyLength)
        {
            var body = new byte[1 + 4 + 1 + keyLength];
            body[0] = 4;
            body[4] = 0x12;
            body[5] = algorithm;
            for (int i = 6; i < body.Length; ++i)
            {
                body[i] = (byte)(i * 3);
            }
            return body;
        }

        [TestCase(99)]
        public void V4PublicSubkeyOfUnknownAlgorithmIsOpaque(byte algorithm)
        {
            PgpUnsupportedVersionTest.GenerateRsaRing(out PgpPublicKeyRing publicRing);
            byte[] extra = NewFormatPacket(PacketTag.PublicSubkey, V4SubkeyBody(algorithm, 40));
            var ring = new PgpPublicKeyRing(Arrays.Concatenate(publicRing.GetEncoded(), extra));

            var keys = ring.GetPublicKeys().ToList();
            Assert.That(keys.Count, Is.EqualTo(publicRing.GetPublicKeys().Count() + 1));

            PgpPublicKey opaque = keys.Last();
            Assert.That((int)opaque.Algorithm, Is.EqualTo((int)algorithm));
            Assert.That(opaque.GetFingerprint().Length, Is.EqualTo(20));
            Assert.Throws<PgpException>(() => opaque.GetKey());

            // the opaque key re-encodes exactly
            Assert.That(Arrays.AreEqual(extra, PgpUnsupportedVersionTest.SplitPackets(ring.GetEncoded()).Last()),
                Is.True);
        }

        [Test]
        public void V4SecretSubkeyOfUnknownAlgorithmIsRejected()
        {
            PgpSecretKeyRing secretRing = PgpUnsupportedVersionTest.GenerateRsaRing(out _);

            // public part, then S2K usage 0 and some secret material
            byte[] body = Arrays.Concatenate(V4SubkeyBody(99, 40), new byte[]{ 0, 1, 2, 3 });
            byte[] extra = NewFormatPacket(PacketTag.SecretSubkey, body);

            Assert.Catch<IOException>(() => new PgpSecretKeyRing(Arrays.Concatenate(secretRing.GetEncoded(), extra)));
        }

        [Test]
        public void SeipdV2HeaderFields()
        {
            // RFC 9980 A.1.3: AES-256, OCB, chunk size octet 12
            byte[] message = PgpV6TestUtilities.LoadRfc9980("a1-message.asc");
            byte[] seipdEncoding = PgpUnsupportedVersionTest.SplitPackets(message)[1];

            var seipd = PgpV6TestUtilities.ReadPacket<SymmetricEncIntegrityPacket>(seipdEncoding);

            Assert.That(seipd.Version, Is.EqualTo(SymmetricEncIntegrityPacket.Version2));
            Assert.That(seipd.CipherAlgorithm, Is.EqualTo(SymmetricKeyAlgorithmTag.Aes256));
            Assert.That(seipd.AeadAlgorithm, Is.EqualTo(AeadAlgorithmTag.Ocb));
            Assert.That(seipd.ChunkSize, Is.EqualTo(12));
            Assert.That(seipd.GetSalt().Length, Is.EqualTo(SymmetricEncIntegrityPacket.SaltLength));
            Assert.That(Hex.ToHexString(seipd.GetAAData()), Is.EqualTo("d20209020c"));
            Assert.That(Arrays.AreEqual(seipd.GetAAData(), SymmetricEncIntegrityPacket.CreateAAData(
                SymmetricKeyAlgorithmTag.Aes256, AeadAlgorithmTag.Ocb, 12)), Is.True);

            // the salt is copied out of the packet
            byte[] salt = seipd.GetSalt();
            int saltOffset = PacketHeaderLength(seipdEncoding) + 4;
            Assert.That(Arrays.AreEqual(Arrays.CopyOfRange(seipdEncoding, saltOffset, saltOffset + 32), salt), Is.True);
            salt[0] ^= 0xFF;
            Assert.That(seipd.GetSalt()[0], Is.Not.EqualTo(salt[0]));

            // the remaining data is the chunked payload
            var remaining = Streams.ReadAll(seipd.GetInputStream());
            Assert.That(remaining.Length, Is.EqualTo(313 - (1 + 3 + 32)));
        }

        [Test]
        public void SeipdV2ChunkSizeOctetIsLimited()
        {
            byte[] Packet(int chunkSize)
            {
                var body = new MemoryStream();
                body.Write(new byte[]{ 2, (byte)SymmetricKeyAlgorithmTag.Aes128, (byte)AeadAlgorithmTag.Gcm,
                    (byte)chunkSize }, 0, 4);
                body.Write(new byte[32 + 16], 0, 32 + 16);
                return NewFormatPacket(PacketTag.SymmetricEncryptedIntegrityProtected, body.ToArray());
            }

            Assert.That(PgpV6TestUtilities.ReadPacket<SymmetricEncIntegrityPacket>(Packet(0)).ChunkSize, Is.EqualTo(0));
            Assert.That(PgpV6TestUtilities.ReadPacket<SymmetricEncIntegrityPacket>(Packet(16)).ChunkSize,
                Is.EqualTo(16));
            Assert.Throws<MalformedPacketException>(() => PgpV6TestUtilities.ReadPacket<SymmetricEncIntegrityPacket>(
                Packet(17)));
            Assert.Throws<MalformedPacketException>(() => PgpV6TestUtilities.ReadPacket<SymmetricEncIntegrityPacket>(
                Packet(255)));
        }

        [Test]
        public void SeipdV2PropertiesRequireVersion2()
        {
            var seipd = SymmetricEncIntegrityPacket.CreateV1Packet();

            Assert.That(seipd.Version, Is.EqualTo(SymmetricEncIntegrityPacket.Version1));
            Assert.Throws<InvalidOperationException>(() => { var x = seipd.CipherAlgorithm; });
            Assert.Throws<InvalidOperationException>(() => { var x = seipd.AeadAlgorithm; });
            Assert.Throws<InvalidOperationException>(() => { var x = seipd.ChunkSize; });
            Assert.Throws<InvalidOperationException>(() => seipd.GetSalt());
            Assert.Throws<InvalidOperationException>(() => seipd.GetAAData());
        }

        [Test]
        public void PaddingInsideAndAfterCertificateIsIgnored()
        {
            PgpUnsupportedVersionTest.GenerateRsaRing(out PgpPublicKeyRing publicRing);
            byte[] encoded = publicRing.GetEncoded();

            byte[] padded = PadAfterEachPacket(encoded);
            Assert.That(padded.Length, Is.GreaterThan(encoded.Length));

            var ring = (PgpPublicKeyRing)new PgpObjectFactory(padded).NextPgpObject();
            Assert.That(Arrays.AreEqual(encoded, ring.GetEncoded()), Is.True);
        }

        [Test]
        public void PaddingBetweenCertificatesInBundleIsIgnored()
        {
            PgpUnsupportedVersionTest.GenerateRsaRing(out PgpPublicKeyRing ring1);
            PgpUnsupportedVersionTest.GenerateRsaRing(out PgpPublicKeyRing ring2);

            byte[] data = Arrays.ConcatenateAll(PaddingPacket(), ring1.GetEncoded(), PaddingPacket(),
                ring2.GetEncoded(), PaddingPacket());

            var bundle = new PgpPublicKeyRingBundle(data);
            Assert.That(bundle.Count, Is.EqualTo(2));
            Assert.That(bundle.GetPublicKeyRing(ring1.GetPublicKey().KeyId), Is.Not.Null);
            Assert.That(bundle.GetPublicKeyRing(ring2.GetPublicKey().KeyId), Is.Not.Null);
        }

        [Test]
        public void PaddingInSecretKeyRingAndBundleIsIgnored()
        {
            PgpSecretKeyRing secretRing1 = PgpUnsupportedVersionTest.GenerateRsaRing(out _);
            PgpSecretKeyRing secretRing2 = PgpUnsupportedVersionTest.GenerateRsaRing(out _);

            byte[] data = Arrays.ConcatenateAll(PaddingPacket(), PadAfterEachPacket(secretRing1.GetEncoded()),
                PadAfterEachPacket(secretRing2.GetEncoded()));

            var bundle = new PgpSecretKeyRingBundle(data);
            Assert.That(bundle.Count, Is.EqualTo(2));
            Assert.That(Arrays.AreEqual(secretRing1.GetEncoded(),
                bundle.GetSecretKeyRing(secretRing1.GetSecretKey().KeyId).GetEncoded()), Is.True);
        }

        [Test]
        public void PaddingBetweenEskPacketsIsIgnored()
        {
            PgpSecretKeyRing secretRing = PgpUnsupportedVersionTest.GenerateRsaRing(out PgpPublicKeyRing publicRing);
            byte[] content = Encoding.ASCII.GetBytes("padded message");
            byte[] message = PgpUnsupportedVersionTest.EncryptTo(publicRing.GetPublicKey(), content);

            // pad after the PKESK only: the payload packet uses partial lengths
            int pkeskLength = FirstPacketLength(message);
            byte[] padded = Arrays.ConcatenateAll(Arrays.CopyOfRange(message, 0, pkeskLength), PaddingPacket(),
                Arrays.CopyOfRange(message, pkeskLength, message.Length));

            var encList = (PgpEncryptedDataList)new PgpObjectFactory(padded).NextPgpObject();
            Assert.That(encList.Count, Is.EqualTo(1));

            var encData = (PgpPublicKeyEncryptedData)encList[0];
            PgpPrivateKey privateKey = secretRing.GetSecretKey().ExtractPrivateKey(new char[0]);
            var literal = (PgpLiteralData)new PgpObjectFactory(encData.GetDataStream(privateKey)).NextPgpObject();
            Assert.That(Arrays.AreEqual(content, Streams.ReadAll(literal.GetDataStream())), Is.True);
        }

        [Test]
        public void PaddingAroundOnePassSignatureIsIgnored()
        {
            PgpSecretKeyRing secretRing = PgpUnsupportedVersionTest.GenerateRsaRing(out _);
            PgpPrivateKey privateKey = secretRing.GetSecretKey().ExtractPrivateKey(new char[0]);
            byte[] content = Encoding.ASCII.GetBytes("signed and padded");

            var sigGen = new PgpSignatureGenerator(PublicKeyAlgorithmTag.RsaGeneral, HashAlgorithmTag.Sha256);
            sigGen.InitSign(PgpSignature.BinaryDocument, privateKey);
            sigGen.Update(content);

            var bOut = new MemoryStream();
            sigGen.GenerateOnePassVersion(false).Encode(bOut);
            using (var lOut = new PgpLiteralDataGenerator().Open(bOut, PgpLiteralData.Binary, "", content.Length,
                DateTime.UtcNow))
            {
                lOut.Write(content, 0, content.Length);
            }
            sigGen.Generate().Encode(bOut);

            // the literal data packet is written with partial lengths, so only pad around the first and last packets
            byte[] data = bOut.ToArray();
            byte[][] packets = PgpUnsupportedVersionTest.SplitPackets(
                Arrays.CopyOfRange(data, 0, data.Length));
            Assert.That(packets.Length, Is.EqualTo(3));

            byte[] padded = Arrays.ConcatenateAll(PaddingPacket(), packets[0], PaddingPacket(), packets[1],
                PaddingPacket(), packets[2], PaddingPacket());

            var factory = new PgpObjectFactory(padded);
            Assert.That(factory.NextPgpObject(), Is.InstanceOf<PgpPadding>());
            var opsList = (PgpOnePassSignatureList)factory.NextPgpObject();
            Assert.That(opsList.Count, Is.EqualTo(1));
            var literal = (PgpLiteralData)factory.NextPgpObject();
            Assert.That(Arrays.AreEqual(content, Streams.ReadAll(literal.GetDataStream())), Is.True);
        }
    }
}
