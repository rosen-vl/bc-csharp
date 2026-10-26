using System;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

using NUnit.Framework;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    [TestFixture]
    public class ArmorCrcTest
    {
        private static readonly string NL = Environment.NewLine;
        private static readonly string WithoutCrc = "" +
            "-----BEGIN PGP MESSAGE-----" + NL +
            NL +
            "yxR0AAAAAABIZWxsbywgV29ybGQhCg==" + NL +
            "-----END PGP MESSAGE-----" + NL;
        private static readonly string FaultyCrc = "" +
            "-----BEGIN PGP MESSAGE-----" + NL +
            NL +
            "yxR0AAAAAABIZWxsbywgV29ybGQhCg==" + NL +
            "=TRA9" + NL +
            "-----END PGP MESSAGE-----";

        [Test]
        public void GenerateArmorWithoutCrcSum()
        {
            MemoryStream bOut = new MemoryStream();
            ArmoredOutputStream armorOut = ArmoredOutputStream.Build()
                .EnableCrc(false)
                .Build(bOut);

            byte[] data = Strings.ToByteArray("Hello, World!\n");

            PgpLiteralDataGenerator litGen = new PgpLiteralDataGenerator();
            using (var litOut = litGen.Open(armorOut, PgpLiteralDataGenerator.Text, "", PgpLiteralData.Now,
                new byte[512]))
            {
                litOut.Write(data, 0, data.Length);
            }
            armorOut.Close();

            string result = Strings.FromByteArray(bOut.ToArray());

            Assert.AreEqual(WithoutCrc, result);
        }

        [Test]
        public void ConsumeArmorWithoutCrc()
        {
            ConsumeSuccessfullyIgnoringCrcSum(WithoutCrc);
            ConsumeSuccessfullyIgnoringCrcSum(FaultyCrc);
        }

        private static void ConsumeSuccessfullyIgnoringCrcSum(string armor)
        {
            MemoryStream bIn = new MemoryStream(Strings.ToByteArray(armor), false);
            ArmoredInputStream armorIn = ArmoredInputStream.Build()
                .SetParseForHeaders(true)
                .setIgnoreCrc(true)
                .SetDetectMissingCrc(false)
                .Build(bIn);

            MemoryStream bOut = new MemoryStream();

            PgpObjectFactory objectFactory = new PgpObjectFactory(armorIn);
            PgpLiteralData literalData = (PgpLiteralData)objectFactory.NextPgpObject();
            using (Stream litIn = literalData.GetDataStream())
            {
                Streams.PipeAll(litIn, bOut);
            }
            armorIn.Close();

            string result = Strings.FromByteArray(bOut.ToArray());

            Assert.AreEqual("Hello, World!\n", result);
        }

        private static readonly SecureRandom Random = new SecureRandom();

        private static readonly string Armored = "" +
            "-----BEGIN PGP MESSAGE-----" + NL +
            NL +
            "yxR0AAAAAABIZWxsbywgV29ybGQhCg==" + NL;

        private static string WithFooter(string footer) => Armored +
            (footer == null ? "" : footer + NL) +
            "-----END PGP MESSAGE-----" + NL;

        private static byte[] ReadArmor(string armor, bool strict)
        {
            var input = new MemoryStream(Strings.ToByteArray(armor), false);
            using (var armorIn = ArmoredInputStream.Build().SetDetectMissingCrc(strict).Build(input))
            {
                return Streams.ReadAll(armorIn);
            }
        }

        private static byte[] ReadDefault(string armor)
        {
            using (var armorIn = new ArmoredInputStream(new MemoryStream(Strings.ToByteArray(armor), false)))
            {
                return Streams.ReadAll(armorIn);
            }
        }

        // RFC 9580 6.1: a missing, malformed or wrong checksum does not invalidate the data, unless asked for
        [TestCase(null, "crc check not found")]
        [TestCase("=TRA9", "crc check failed in armored message.")]
        [TestCase("=TRA", "malformed crc in armored message.")]
        [TestCase("=TRA9A", "malformed crc in armored message.")]
        [TestCase("=TR!9", "malformed crc in armored message.")]
        [TestCase("=", "malformed crc in armored message.")]
        public void BadChecksumsAreOnlyRejectedWhenStrict(string footer, string message)
        {
            string armor = WithFooter(footer);
            byte[] expected = ReadArmor(WithFooter(null), strict: false);

            Assert.That(ReadDefault(armor), Is.EqualTo(expected));
            Assert.That(ReadArmor(armor, strict: false), Is.EqualTo(expected));

            var e = Assert.Throws<ArmoredInputException>(() => ReadArmor(armor, strict: true));
            Assert.That(e.Message, Is.EqualTo(message));
        }

        [Test]
        public void CorrectChecksumPassesStrictChecking()
        {
            byte[] data = ReadArmor(WithFooter(null), strict: false);
            string armor = Armor(data, crc: true);
            Assert.That(HasCrc(armor), Is.True);
            Assert.That(ReadArmor(armor, strict: true), Is.EqualTo(data));
        }

        [Test]
        public void MultipleChecksumsAreRejected()
        {
            string armor = Armored + "=TRA9" + NL + "=TRA9" + NL + "-----END PGP MESSAGE-----" + NL;
            Assert.Throws<ArmoredInputException>(() => ReadArmor(armor, strict: false));
        }

        private static string Armor(byte[] data, bool? crc = null)
        {
            var bOut = new MemoryStream();
            var armorOut = crc.HasValue
                ? ArmoredOutputStream.Build().EnableCrc(crc.Value).Build(bOut)
                : new ArmoredOutputStream(bOut);
            armorOut.Write(data, 0, data.Length);
            armorOut.Close();

            string armor = Strings.FromByteArray(bOut.ToArray());
            Assert.That(ReadArmor(armor, strict: false), Is.EqualTo(data));
            return armor;
        }

        private static bool HasCrc(string armor) =>
            Regex.IsMatch(armor, "^=[A-Za-z0-9+/]{4}\r?$", RegexOptions.Multiline);

        private static void CheckCrc(byte[] data, bool expectCrc)
        {
            Assert.That(HasCrc(Armor(data)), Is.EqualTo(expectCrc), "default");
            Assert.That(HasCrc(ArmorWithBuilder(data)), Is.EqualTo(expectCrc), "builder");

            // an explicit choice applies to all data
            Assert.That(HasCrc(Armor(data, crc: true)), Is.True);
            Assert.That(HasCrc(Armor(data, crc: false)), Is.False);
        }

        private static string ArmorWithBuilder(byte[] data)
        {
            var bOut = new MemoryStream();
            using (var armorOut = ArmoredOutputStream.Build().Build(bOut))
            {
                armorOut.Write(data, 0, data.Length);
            }
            return Strings.FromByteArray(bOut.ToArray());
        }

        // RFC 9580 6.1: no checksum for version 6 keys, and for messages that end in a version 2 SEIPD packet
        [TestCase("a3-v6-certificate.asc", false)]
        [TestCase("a4-v6-secret-key.asc", false)]
        [TestCase("a8-x25519-ocb-message.asc", false)]
        [TestCase("a9-eax-message.asc", false)]
        [TestCase("a1-v4-ed25519legacy-key.asc", true)]
        [TestCase("a2-v4-ed25519legacy-signature.asc", true)]
        [TestCase("a7-inline-signed.asc", true)]
        public void ChecksumOfRfc9580Vectors(string name, bool expectCrc) =>
            CheckCrc(PgpV6TestUtilities.LoadRfc9580(name), expectCrc);

        [Test]
        public void KeyringsWithoutChecksumHaveOnlyVersion6Keys()
        {
            byte[] v6 = PgpV6TestUtilities.LoadRfc9580("a3-v6-certificate.asc");
            byte[] v4 = PgpV6TestUtilities.LoadRfc9580("a1-v4-ed25519legacy-key.asc");

            CheckCrc(Arrays.Concatenate(v6, v6), expectCrc: false);
            CheckCrc(Arrays.Concatenate(v6, v4), expectCrc: true);
            CheckCrc(Arrays.Concatenate(v4, v6), expectCrc: true);
        }

        [Test]
        public void SignaturesWithoutChecksumAreAllVersion6()
        {
            byte[] v6 = new PgpPublicKeyRing(PgpV6TestUtilities.LoadRfc9580("a3-v6-certificate.asc")).GetPublicKey()
                .GetSignatures().First().GetEncoded();
            byte[] v4 = PgpV6TestUtilities.LoadRfc9580("a2-v4-ed25519legacy-signature.asc");

            CheckCrc(v6, expectCrc: false);
            CheckCrc(Arrays.Concatenate(v6, v6), expectCrc: false);
            CheckCrc(Arrays.Concatenate(v6, v4), expectCrc: true);
        }

        [Test]
        public void MessagesWithoutChecksumEndInSeipdV2([Values(false, true)] bool partial)
        {
            byte[] plaintext = SecureRandom.GetNextBytes(Random, 5000);

            byte[] v2 = PgpAeadEncryptionTest.Encrypt(SymmetricKeyAlgorithmTag.Aes128, AeadAlgorithmTag.Ocb, 0,
                plaintext, partial);
            CheckCrc(v2, expectCrc: false);

            // padding packets do not count
            byte[] padding = PgpV6TestUtilities.NewFormatPacket(PacketTag.Padding, new byte[300]);
            CheckCrc(Arrays.Concatenate(v2, padding), expectCrc: false);

            var generator = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes128, true, Random);
            generator.AddMethod("pass".ToCharArray(), HashAlgorithmTag.Sha256);
            var bOut = new MemoryStream();
            using (Stream encOut = partial
                ? generator.Open(bOut, new byte[1 << 9])
                : generator.Open(bOut, plaintext.Length))
            {
                encOut.Write(plaintext, 0, plaintext.Length);
            }
            CheckCrc(bOut.ToArray(), expectCrc: true);
        }
    }
}
