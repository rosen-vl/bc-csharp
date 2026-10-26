using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Bcpg.Sig;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Tools.PgpInterop
{
    /// <summary>Exit codes of the Stateless OpenPGP command line interface.</summary>
    internal static class ExitCode
    {
        internal const int Ok = 0;
        internal const int NoSignature = 3;
        internal const int CertCannotEncrypt = 17;
        internal const int MissingArg = 19;
        internal const int CannotDecrypt = 29;
        internal const int UnsupportedOption = 37;
        internal const int BadData = 41;
        internal const int OutputExists = 59;
        internal const int MissingInput = 61;
        internal const int KeyIsProtected = 67;
        internal const int UnsupportedSubcommand = 69;
        internal const int UnsupportedSpecialPrefix = 71;
        internal const int KeyCannotSign = 79;
        internal const int UnsupportedProfile = 89;
    }

    internal sealed class SopException
        : Exception
    {
        internal SopException(int exitCode, string message)
            : base(message)
        {
            ExitCode = exitCode;
        }

        internal int ExitCode { get; }
    }

    /// <summary>
    /// A subset of the Stateless OpenPGP CLI (draft-dkg-openpgp-stateless-cli) over Bouncy Castle, used to test
    /// RFC 9580 and RFC 9980 interoperability.
    /// </summary>
    internal static partial class Program
    {
        private const string Version = "0.2";

        private static readonly SecureRandom Random = new SecureRandom();

        /// <summary>With <c>--debug</c>, the exception behind a failure is printed.</summary>
        private static bool Debug => Environment.GetCommandLineArgs().Contains("--debug");

        private static int Main(string[] args)
        {
            try
            {
                return Run(new Arguments(args));
            }
            catch (SopException e)
            {
                Console.Error.WriteLine(e.Message);
                return e.ExitCode;
            }
        }

        private static int Run(Arguments args)
        {
            switch (args.Subcommand)
            {
            case "version":
                return PrintVersion(args);
            case "list-profiles":
                return ListProfiles(args);
            case "generate-key":
                return GenerateKey(args);
            case "extract-cert":
                return ExtractCert(args);
            case "encrypt":
                return Encrypt(args);
            case "decrypt":
                return Decrypt(args);
            case "sign":
                return Sign(args);
            case "verify":
                return Verify(args);
            case "inline-sign":
                return InlineSign(args);
            case "inline-verify":
                return InlineVerify(args);
            case "armor":
                return Armor(args);
            case "dearmor":
                return Dearmor(args);
            case "x-packets":
                return DumpPackets(args);
            default:
                throw new SopException(ExitCode.UnsupportedSubcommand, "unsupported subcommand: " + args.Subcommand);
            }
        }

        private static int PrintVersion(Arguments args)
        {
            args.Finish();
            Console.WriteLine("bcsop " + Version);
            return ExitCode.Ok;
        }

        private static int ListProfiles(Arguments args)
        {
            string subcommand = args.RequirePositional("subcommand");
            args.Finish();
            switch (subcommand)
            {
            case "generate-key":
                foreach (KeyProfile profile in KeyProfiles)
                {
                    Console.WriteLine(profile.Name + ": " + profile.Description +
                        (profile.Alias == null ? "" : " (alias: " + profile.Alias + ")"));
                }
                return ExitCode.Ok;
            case "encrypt":
                Console.WriteLine("default: the format and the algorithms that the recipients' preferences select");
                Console.WriteLine("seipdv1: v3 PKESK and v1 SEIPD with AES-256 (alias: rfc9580-v1)");
                Console.WriteLine("seipdv2: v6 PKESK and v2 SEIPD with AES-256 and OCB");
                Console.WriteLine("seipdv2-gcm: v6 PKESK and v2 SEIPD with AES-256 and GCM");
                Console.WriteLine("seipdv2-eax: v6 PKESK and v2 SEIPD with AES-256 and EAX");
                return ExitCode.Ok;
            default:
                throw new SopException(ExitCode.UnsupportedProfile, "no profiles for " + subcommand);
            }
        }

        private static int ExtractCert(Arguments args)
        {
            bool armor = !args.Flag("--no-armor");
            args.Finish();

            List<PgpSecretKeyRing> rings = ReadSecretRings(ReadStdin());
            if (rings.Count == 0)
                throw new SopException(ExitCode.BadData, "no secret key found");

            WriteOutput(armor, outStr =>
            {
                foreach (var ring in rings)
                {
                    foreach (PgpSecretKey secretKey in ring.GetSecretKeys())
                    {
                        secretKey.PublicKey.Encode(outStr, forTransfer: true);
                    }
                }
            });
            return ExitCode.Ok;
        }

        // ---------------------------------------------------------------- encrypt

        private static int Encrypt(Arguments args)
        {
            bool armor = !args.Flag("--no-armor");
            bool text = ParseAs(args);
            string profile = ParseEncryptProfile(args);
            List<string> signerFiles = args.Options("--sign-with");
            List<char[]> keyPasswords = args.Options("--with-key-password").Select(ReadPassword).ToList();
            List<char[]> passwords = args.Options("--with-password").Select(ReadPassword).ToList();
            List<string> certFiles = args.RemainingPositionals();
            args.Finish();

            if (certFiles.Count == 0 && passwords.Count == 0)
                throw new SopException(ExitCode.MissingArg, "no certificates or passwords given");

            var certificates = new List<PgpPublicKeyRing>();
            var recipients = new List<PgpPublicKey>();
            foreach (string certFile in certFiles)
            {
                foreach (PgpPublicKeyRing cert in ReadPublicRings(ReadFile(certFile)))
                {
                    List<PgpPublicKey> selected = SelectRecipients(cert);
                    if (selected.Count == 0)
                        throw new SopException(ExitCode.CertCannotEncrypt, "no usable encryption key in " + certFile);

                    certificates.Add(cert);
                    recipients.AddRange(selected);
                }
            }

            var signers = signerFiles.SelectMany(f => ReadSecretRings(ReadFile(f)))
                .Select(ring => SigningKey(ring, keyPasswords)).ToList();

            byte[] content = ReadStdin();

            PgpEncryptedDataGenerator encGen = CreateEncryptedDataGenerator(profile, certificates, out bool v2);
            foreach (PgpPublicKey recipient in recipients)
            {
                encGen.AddMethod(recipient);
            }
            foreach (char[] password in passwords)
            {
                if (v2)
                {
                    encGen.AddMethod(password, Org.BouncyCastle.Bcpg.S2k.Argon2Params.MemoryConstrainedParameters(Random));
                }
                else
                {
                    encGen.AddMethod(password, HashAlgorithmTag.Sha256);
                }
            }

            WriteOutput(armor, outStr =>
            {
                using (Stream encOut = encGen.Open(outStr, new byte[1 << 16]))
                {
                    WriteSignedContent(encOut, signers, certificates.Select(c => c.GetPublicKey()).ToList(), content, text);
                }
            });
            return ExitCode.Ok;
        }

        private static string ParseEncryptProfile(Arguments args)
        {
            string requested = args.Option("--profile") ?? "default";
            switch (requested)
            {
            case "default":
                return "default";
            case "seipdv1":
            case "rfc9580-v1":
                return "seipdv1";
            case "seipdv2":
            case "seipdv2-gcm":
            case "seipdv2-eax":
                return requested;
            default:
                throw new SopException(ExitCode.UnsupportedProfile, "unsupported profile: " + requested);
            }
        }

        /// <summary>
        /// The format and the algorithms of the message: those that the preferences of the recipients select, unless
        /// a profile forces version 1 or version 2 SEIPD packets.
        /// </summary>
        private static PgpEncryptedDataGenerator CreateEncryptedDataGenerator(string profile,
            List<PgpPublicKeyRing> certificates, out bool v2)
        {
            PgpEncryptionPreferences preferences = certificates.Count == 0
                ? null
                : PgpEncryptionPreferences.Select(certificates);

            switch (profile)
            {
            case "seipdv1":
                v2 = false;
                return new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, true, Random);
            case "seipdv2":
                v2 = true;
                return new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, AeadAlgorithmTag.Ocb, Random);
            case "seipdv2-gcm":
                v2 = true;
                return new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, AeadAlgorithmTag.Gcm, Random);
            case "seipdv2-eax":
                v2 = true;
                return new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, AeadAlgorithmTag.Eax, Random);
            default:
                v2 = preferences != null && preferences.UseSeipdV2;
                return preferences != null
                    ? preferences.CreateGenerator(Random)
                    : new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, true, Random);
            }
        }

        /// <summary>
        /// The valid encryption subkeys of a certificate that Bouncy Castle can use. If any ML-KEM composite subkey
        /// is usable, only those are returned, so that the message is not weakened by also encrypting to a
        /// traditional key.
        /// </summary>
        private static List<PgpPublicKey> SelectRecipients(PgpPublicKeyRing cert)
        {
            PgpPublicKey primary = cert.GetPublicKey();
            DateTime now = DateTime.UtcNow;
            var usable = new List<PgpPublicKey>();
            if (!IsValidPrimary(primary, now))
                return usable;

            foreach (PgpPublicKey key in cert.GetPublicKeys())
            {
                if (key.IsMasterKey || !key.IsEncryptionKey)
                    continue;
                if (key.Version != PublicKeyPacket.Version4 && key.Version != PublicKeyPacket.Version6)
                    continue;
                if (key.Algorithm == PublicKeyAlgorithmTag.ElGamalEncrypt ||
                    key.Algorithm == PublicKeyAlgorithmTag.ElGamalGeneral)
                    continue;
                PgpSignature binding = NewestValidBinding(primary, key, now);
                if (!IsValidSubkey(primary, key, binding, now) || !HasEncryptionFlags(binding))
                    continue;

                try
                {
                    key.GetKey();
                }
                catch (PgpException)
                {
                    continue;
                }

                usable.Add(key);
            }

            var postQuantum = usable.Where(k => k.Algorithm == PublicKeyAlgorithmTag.MLKem768_X25519 ||
                k.Algorithm == PublicKeyAlgorithmTag.MLKem1024_X448).ToList();
            return postQuantum.Count > 0 ? postQuantum : usable;
        }

        private static bool HasEncryptionFlags(PgpSignature binding)
        {
            var hashed = binding.GetHashedSubPackets();
            if (hashed == null || !hashed.HasSubpacket(SignatureSubpacketTag.KeyFlags))
                return true;

            int flags = hashed.GetKeyFlags();
            return (flags & (PgpKeyFlags.CanEncryptCommunications | PgpKeyFlags.CanEncryptStorage)) != 0;
        }

        /// <summary>
        /// The key to sign with: a currently valid subkey whose binding signature allows signing (with a valid
        /// embedded primary key binding signature), else the primary key if its self-signatures allow signing.
        /// Implementations such as Sequoia generate certification-only primary keys with a separate signing subkey;
        /// a signature by such a primary key is rightly rejected by them.
        /// </summary>
        private static PgpPrivateKey SigningKey(PgpSecretKeyRing ring, List<char[]> passwords)
        {
            PgpPublicKey primary = ring.GetPublicKey();
            DateTime now = DateTime.UtcNow;
            var candidates = new List<PgpSecretKey>();

            foreach (PgpSecretKey secretKey in ring.GetSecretKeys())
            {
                if (secretKey.IsMasterKey || !secretKey.IsSigningKey || secretKey.IsPrivateKeyEmpty)
                    continue;

                PgpPublicKey subkey = secretKey.PublicKey;
                PgpSignature binding = NewestValidBinding(primary, subkey, now);
                if (!IsValidSubkey(primary, subkey, binding, now) ||
                    !HasFlag(binding, PgpKeyFlags.CanSign, ifAbsent: false) ||
                    !HasValidBackSignature(primary, subkey, binding))
                {
                    continue;
                }
                candidates.Add(secretKey);
            }

            PgpSecretKey primarySecret = ring.GetSecretKey();
            if (!IsValidPrimary(primary, now))
                throw new SopException(ExitCode.KeyCannotSign, "key cannot sign");
            if (primarySecret.IsSigningKey && !primarySecret.IsPrivateKeyEmpty && PrimaryAllowsSigning(primary, now))
            {
                candidates.Add(primarySecret);
            }

            if (candidates.Count == 0)
                throw new SopException(ExitCode.KeyCannotSign, "key cannot sign");

            foreach (PgpSecretKey candidate in candidates)
            {
                PgpPrivateKey privateKey = ExtractPrivateKey(candidate, passwords);
                if (privateKey != null)
                    return privateKey;
            }
            throw new SopException(ExitCode.KeyIsProtected, "cannot unlock signing key");
        }

        private static bool HasFlag(PgpSignature signature, int flag, bool ifAbsent)
        {
            var hashed = signature.GetHashedSubPackets();
            if (hashed == null || !hashed.HasSubpacket(SignatureSubpacketTag.KeyFlags))
                return ifAbsent;

            return (hashed.GetKeyFlags() & flag) != 0;
        }

        /// <summary>A signature packet with the given body, with a new-format header (RFC 9580 4.2.1).</summary>
        private static byte[] SignaturePacketOf(byte[] body)
        {
            var packet = new MemoryStream();
            packet.WriteByte(0xC0 | (int)PacketTag.Signature);
            if (body.Length < 192)
            {
                packet.WriteByte((byte)body.Length);
            }
            else if (body.Length <= 8383)
            {
                packet.WriteByte((byte)(((body.Length - 192) >> 8) + 192));
                packet.WriteByte((byte)(body.Length - 192));
            }
            else
            {
                packet.WriteByte(0xFF);
                packet.Write(new[]{ (byte)(body.Length >> 24), (byte)(body.Length >> 16), (byte)(body.Length >> 8),
                    (byte)body.Length }, 0, 4);
            }
            packet.Write(body, 0, body.Length);
            return packet.ToArray();
        }

        private static void AddAll(List<PgpSignature> list, PgpSignatureList signatures)
        {
            for (int i = 0; i < signatures.Count; ++i)
            {
                list.Add(signatures[i]);
            }
        }

        /// <summary>
        /// The embedded signatures of a subpacket area that can be read: a malformed one is skipped and does not
        /// spoil the others (RFC 9580 5.2.5).
        /// </summary>
        private static void AddEmbedded(List<PgpSignature> list, PgpSignatureSubpacketVector subpackets)
        {
            if (subpackets == null)
                return;

            foreach (SignatureSubpacket subpacket in subpackets.GetSubpackets(SignatureSubpacketTag.EmbeddedSignature))
            {
                try
                {
                    // the body as it is, in a packet of its own: encoding a parsed packet again would drop what
                    // makes it malformed
                    AddAll(list, (PgpSignatureList)new PgpObjectFactory(SignaturePacketOf(subpacket.GetData()))
                        .NextPgpObject());
                }
                catch (Exception e) when (e is IOException || e is PgpException)
                {
                }
            }
        }

        /// <summary>The embedded primary key binding signature that signing subkeys need (RFC 9580 10.1.5).</summary>
        private static bool HasValidBackSignature(PgpPublicKey primary, PgpPublicKey subkey, PgpSignature binding)
        {
            var embedded = new List<PgpSignature>();
            AddEmbedded(embedded, binding.GetHashedSubPackets());
            AddEmbedded(embedded, binding.GetUnhashedSubPackets());

            foreach (PgpSignature backSignature in embedded)
            {
                if (backSignature.SignatureType != PgpSignature.PrimaryKeyBinding)
                    continue;
                try
                {
                    backSignature.InitVerify(subkey);
                    if (backSignature.VerifyCertification(primary, subkey))
                        return true;
                }
                catch (PgpException)
                {
                }
            }
            return false;
        }

        private static PgpPrivateKey ExtractPrivateKey(PgpSecretKey secretKey, List<char[]> passwords)
        {
            var candidates = new List<char[]>{ new char[0] };
            candidates.AddRange(passwords);
            foreach (char[] password in candidates)
            {
                try
                {
                    PgpPrivateKey privateKey = secretKey.ExtractPrivateKey(password);
                    if (privateKey != null)
                        return privateKey;
                }
                catch (PgpException)
                {
                }
            }
            return null;
        }

        // ---------------------------------------------------------------- signing

        /// <summary>
        /// Write one-pass signatures, the literal data and the signatures. The signatures name the primary keys of the
        /// recipients' certificates (RFC 9580 5.2.3.36; this is what the test vectors and the other implementations do).
        /// The subpacket is not marked critical: OpenPGP.js rejects signatures with critical subpackets it does not know.
        /// </summary>
        private static void WriteSignedContent(Stream outStr, List<PgpPrivateKey> signers,
            List<PgpPublicKey> recipients, byte[] content, bool text)
        {
            int signatureType = text ? PgpSignature.CanonicalTextDocument : PgpSignature.BinaryDocument;

            var sigGens = new List<PgpSignatureGenerator>();
            foreach (var signer in signers)
            {
                var sigGen = new PgpSignatureGenerator(signer.PublicKeyPacket.Algorithm, HashAlgorithmTag.Sha512);
                sigGen.InitSign(signatureType, signer);
                if (recipients.Count > 0)
                {
                    // RFC 9580 5.2.3.36: the fingerprints of the recipients' primary keys. The RFC says the subpacket
                    // SHOULD be critical in v6 signatures, but OpenPGP.js 6.3.1 rejects the signature then ("unknown
                    // critical signature subpacket type 35"), so it is not.
                    var subpackets = new PgpSignatureSubpacketGenerator();
                    foreach (PgpPublicKey recipient in recipients)
                    {
                        subpackets.AddIntendedRecipientFingerprint(isCritical: false, recipient);
                    }
                    sigGen.SetHashedSubpackets(subpackets.Generate());
                }
                sigGens.Add(sigGen);
            }
            for (int i = 0; i < sigGens.Count; ++i)
            {
                sigGens[i].GenerateOnePassVersion(i < sigGens.Count - 1).Encode(outStr);
            }

            char format = text ? PgpLiteralData.Utf8 : PgpLiteralData.Binary;
            using (var litOut = new PgpLiteralDataGenerator().Open(outStr, format, "", content.Length,
                DateTime.UtcNow))
            {
                litOut.Write(content, 0, content.Length);
            }

            for (int i = sigGens.Count - 1; i >= 0; --i)
            {
                sigGens[i].Update(content);
                sigGens[i].Generate().Encode(outStr);
            }
        }

        // ---------------------------------------------------------------- decrypt

        private static int Decrypt(Arguments args)
        {
            List<string> verifyWith = args.Options("--verify-with");
            string verificationsOut = args.Option("--verifications-out");
            List<char[]> keyPasswords = args.Options("--with-key-password").Select(ReadPassword).ToList();
            List<char[]> messagePasswords = args.Options("--with-password").Select(ReadPassword).ToList();
            DateTime? notBefore = ParseDate(args.Option("--verify-not-before"));
            DateTime? notAfter = ParseDate(args.Option("--verify-not-after"));
            if (args.Option("--session-key-out") != null || args.Options("--with-session-key").Count > 0)
                throw new SopException(ExitCode.UnsupportedOption, "unsupported option");
            List<string> keyFiles = args.RemainingPositionals();
            args.Finish();

            if (verificationsOut != null && File.Exists(verificationsOut))
                throw new SopException(ExitCode.OutputExists, "output exists: " + verificationsOut);
            if (keyFiles.Count == 0 && messagePasswords.Count == 0)
                throw new SopException(ExitCode.MissingArg, "no keys or passwords given");

            var secretRings = keyFiles.SelectMany(f => ReadSecretRings(ReadFile(f))).ToList();
            var secretKeys = secretRings.SelectMany(r => r.GetSecretKeys()).ToList();
            var verifyCerts = verifyWith.SelectMany(f => ReadPublicRings(ReadFile(f))).ToList();

            byte[] message = ReadStdin();
            Content content;
            try
            {
                content = DecryptMessage(message, secretRings, secretKeys, keyPasswords, messagePasswords,
                    new SignatureWindow(notBefore, notAfter), verifyCerts);
            }
            catch (SopException)
            {
                throw;
            }
            catch (Exception e)
            {
                // A single error for every kind of failure (RFC 9580 13.5)
                if (Debug)
                {
                    Console.Error.WriteLine(e);
                }
                throw new SopException(ExitCode.CannotDecrypt, "cannot decrypt");
            }

            if (verificationsOut != null)
            {
                File.WriteAllText(verificationsOut, string.Concat(content.Verifications.Select(v => v + "\n")));
            }

            // Plaintext is only released after the integrity check succeeded
            using (Stream stdout = Console.OpenStandardOutput())
            {
                stdout.Write(content.Data, 0, content.Data.Length);
            }
            return ExitCode.Ok;
        }

        private sealed class Content
        {
            internal byte[] Data;
            internal List<string> Verifications = new List<string>();
        }

        /// <summary>The creation times that signatures need to have to count.</summary>
        private sealed class SignatureWindow
        {
            internal static readonly SignatureWindow Unlimited = new SignatureWindow(null, null);

            private readonly DateTime? m_notBefore, m_notAfter;

            internal SignatureWindow(DateTime? notBefore, DateTime? notAfter)
            {
                m_notBefore = notBefore;
                m_notAfter = notAfter;
            }

            internal bool Contains(PgpSignature signature)
            {
                DateTime created = signature.CreationTime.ToUniversalTime();
                return (!m_notBefore.HasValue || created >= m_notBefore.Value)
                    && (!m_notAfter.HasValue || created <= m_notAfter.Value);
            }
        }

        private static Content DecryptMessage(byte[] message, List<PgpSecretKeyRing> secretRings,
            List<PgpSecretKey> secretKeys, List<char[]> keyPasswords, List<char[]> messagePasswords, SignatureWindow window,
            List<PgpPublicKeyRing> verifyCerts)
        {
            var factory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(new MemoryStream(message, false)));
            PgpObject obj = factory.NextPgpObject();
            while (obj is PgpMarker || obj is PgpPadding)
            {
                obj = factory.NextPgpObject();
            }
            if (!(obj is PgpEncryptedDataList encList))
                throw new SopException(ExitCode.BadData, "not an encrypted message");

            bool lockedKey = false;
            foreach (PgpPublicKeyEncryptedData encData in encList.GetEncryptedDataObjects()
                .OfType<PgpPublicKeyEncryptedData>())
            {
                IEnumerable<PgpSecretKey> candidates = encData.KeyId == 0
                    ? secretKeys.Where(k => k.PublicKey.IsEncryptionKey)
                    : secretKeys.Where(k => k.KeyId == encData.KeyId);

                foreach (PgpSecretKey secretKey in candidates)
                {
                    PgpPrivateKey privateKey;
                    try
                    {
                        privateKey = ExtractPrivateKey(secretKey, keyPasswords);
                    }
                    catch (Exception)
                    {
                        privateKey = null;
                    }
                    if (privateKey == null)
                    {
                        lockedKey |= secretKey.KeyEncryptionAlgorithm != SymmetricKeyAlgorithmTag.Null;
                        continue;
                    }

                    Stream clear;
                    try
                    {
                        clear = encData.GetDataStream(privateKey);
                    }
                    catch (PgpException) when (encData.KeyId == 0)
                    {
                        continue;
                    }

                    // the recipients that a signature names are keys of the certificate of the decrypting key
                    PgpSecretKeyRing ring = secretRings.First(r => r.GetSecretKey(secretKey.KeyId) != null);
                    Content content = ReadContent(clear, verifyCerts, window,
                        ring.GetPublicKeys().Select(k => k.GetFingerprint()).ToList());
                    if (!encData.Verify())
                        throw new SopException(ExitCode.CannotDecrypt, "cannot decrypt");
                    RequireEndOfMessage(factory);

                    return content;
                }
            }

            foreach (PgpPbeEncryptedData pbeData in encList.GetEncryptedDataObjects().OfType<PgpPbeEncryptedData>())
            {
                foreach (char[] password in messagePasswords)
                {
                    Stream clear;
                    try
                    {
                        clear = pbeData.GetDataStream(password);
                    }
                    catch (PgpException)
                    {
                        continue;
                    }

                    Content content = ReadContent(clear, verifyCerts, window, null);
                    if (!pbeData.Verify())
                        throw new SopException(ExitCode.CannotDecrypt, "cannot decrypt");
                    RequireEndOfMessage(factory);

                    return content;
                }
            }

            if (lockedKey)
                throw new SopException(ExitCode.KeyIsProtected, "key is password protected");

            throw new SopException(ExitCode.CannotDecrypt, "cannot decrypt");
        }

        /// <summary>
        /// Read signed or plain content. A signature that names intended recipients only counts if the key that
        /// decrypted the message is one of them.
        /// </summary>
        /// <remarks>
        /// The packet sequence has to be exactly one OpenPGP Message (RFC 9580 10.3): optional signatures, then a
        /// literal or a compressed message, then the signatures of the one-pass signatures. Markers, padding and
        /// non-critical unknown packets are skipped anywhere (RFC 9580 4.3, 5.14); anything else, such as a second
        /// literal, a key, or an unknown critical packet, rejects the message (RFC 9580 10).
        /// </remarks>
        private static Content ReadContent(Stream clear, List<PgpPublicKeyRing> verifyCerts, SignatureWindow window,
            List<byte[]> recipientFingerprints)
        {
            var content = new Content();
            ReadMessage(new PgpObjectFactory(clear), verifyCerts, window, recipientFingerprints, content, 0);
            if (content.Data == null)
                throw new SopException(ExitCode.BadData, "no literal data");

            return content;
        }

        private const int MaxMessageNesting = 16;

        private static void ReadMessage(PgpObjectFactory factory, List<PgpPublicKeyRing> verifyCerts,
            SignatureWindow window, List<byte[]> recipientFingerprints, Content content, int depth)
        {
            if (depth > MaxMessageNesting)
                throw new SopException(ExitCode.BadData, "message nested too deeply");

            var onePass = new List<OnePassEntry>();
            int onePassCount = 0, signatureCount = 0;
            bool haveSignatures = false;
            // whether the parser left one-pass signatures or signatures out, which shifts the brackets
            bool shifted = false;
            bool onePassUpdated = false;
            var prefixSignatures = new List<PgpSignature>();
            bool haveBody = false;

            PgpObject obj;
            while ((obj = NextMessageObject(factory)) != null)
            {
                if (Debug)
                {
                    Console.Error.WriteLine("object: " + obj.GetType().Name);
                }

                if (!haveBody && obj is PgpOnePassSignatureList opsList)
                {
                    // those of unsupported versions are left out, but their signatures follow (RFC 9580 5.2.5)
                    onePassCount += opsList.Count + opsList.UnsupportedCount;
                    shifted |= opsList.UnsupportedCount > 0;
                    for (int i = 0; i < opsList.Count; ++i)
                    {
                        // every one-pass signature has its place in the brackets, also without a key to verify it;
                        // whether the key signs for its certificate depends on the time of the signature
                        PgpOnePassSignature ops = opsList[i];
                        var entry = new OnePassEntry{ Ops = ops };
                        foreach (var cert in verifyCerts)
                        {
                            PgpPublicKey key = cert.GetPublicKey(ops.KeyId);
                            if (key != null && TryInitVerify(ops, key))
                            {
                                entry.Key = key;
                                entry.Cert = cert;
                                break;
                            }
                        }
                        onePass.Add(entry);
                    }
                }
                else if (!haveBody && obj is PgpSignatureList prefixList)
                {
                    // Signed Message: Signature Packet, OpenPGP Message (also nested in a one-pass signed message)
                    for (int i = 0; i < prefixList.Count; ++i)
                    {
                        prefixSignatures.Add(prefixList[i]);
                    }
                }
                else if (!haveBody && obj is PgpLiteralData literal)
                {
                    content.Data = Streams.ReadAll(literal.GetDataStream());
                    haveBody = true;
                }
                else if (!haveBody && obj is PgpCompressedData compressed)
                {
                    ReadMessage(new PgpObjectFactory(compressed.GetDataStream()), verifyCerts, window,
                        recipientFingerprints, content, depth + 1);
                    haveBody = true;
                }
                else if (haveBody && obj is PgpSignatureList sigList && signatureCount < onePassCount)
                {
                    // One-pass signatures are matched with the signatures in reverse order (RFC 9580 5.4).
                    // Malformed or unusable signatures are ignored (5.2.5).
                    haveSignatures = true;
                    signatureCount += sigList.Count + sigList.UnsupportedCount;
                    shifted |= sigList.UnsupportedCount > 0;
                    if (signatureCount > onePassCount)
                        throw new SopException(ExitCode.BadData, "more signatures than one-pass signatures");

                    if (!onePassUpdated)
                    {
                        foreach (var entry in onePass.Where(e => e.Key != null))
                        {
                            entry.Ops.Update(content.Data);
                        }
                        onePassUpdated = true;
                    }

                    for (int i = 0; i < sigList.Count; ++i)
                    {
                        PgpSignature signature = sigList[i];
                        OnePassEntry entry = MatchingOnePass(onePass, signature, shifted);
                        if (entry == null)
                            continue;

                        if (entry.Key != null && IsValidDocumentSignature(signature) && window.Contains(signature) &&
                            CanSignFor(entry.Cert, entry.Key, signature.CreationTime) &&
                            NamesRecipient(signature, recipientFingerprints) && TryVerify(entry.Ops, signature))
                        {
                            content.Verifications.Add(VerificationLine(signature, entry.Key, entry.Cert,
                                ModeOf(signature)));
                        }
                    }
                }
                else
                {
                    throw new SopException(ExitCode.BadData, "unexpected " + Describe(obj) + " in the message");
                }
            }

            // Fewer signatures than one-pass signatures is not an error: the parser drops signatures of unknown
            // versions, and the other signatures still count (RFC 9580 5.2.5); a missing signature does not verify.
            // But one-pass signatures without any signature packet after the literal data are malformed (10.3).
            if (!haveBody)
                throw new SopException(ExitCode.BadData, "no literal data");
            if (onePassCount > 0 && !haveSignatures)
                throw new SopException(ExitCode.BadData, "one-pass signatures without signatures");

            foreach (PgpSignature signature in prefixSignatures)
            {
                foreach (var cert in verifyCerts)
                {
                    PgpPublicKey key = cert.GetPublicKey(signature.KeyId);
                    if (key != null && IsValidDocumentSignature(signature) &&
                        CanSignFor(cert, key, signature.CreationTime) &&
                        window.Contains(signature) && NamesRecipient(signature, recipientFingerprints) &&
                        TryVerifyData(signature, key, content.Data))
                    {
                        content.Verifications.Add(VerificationLine(signature, key, cert, ModeOf(signature)));
                        break;
                    }
                }
            }
        }

        private sealed class OnePassEntry
        {
            internal PgpOnePassSignature Ops;
            internal PgpPublicKey Key;
            internal PgpPublicKeyRing Cert;
            internal bool Used;
        }

        /// <summary>
        /// The one-pass signature that a signature closes, or null. One-pass signatures and their signatures are
        /// bracketed (RFC 9580 5.4): a signature closes the innermost one that is still open, and verifies only if
        /// it is for that one. If the parser left one-pass signatures or signatures out (5.2.5), the brackets have
        /// shifted, and a signature closes the innermost open one that is for it, so that no other pair is lost.
        /// </summary>
        private static OnePassEntry MatchingOnePass(List<OnePassEntry> onePass, PgpSignature signature,
            bool shifted)
        {
            for (int i = onePass.Count - 1; i >= 0; --i)
            {
                OnePassEntry entry = onePass[i];
                if (entry.Used)
                    continue;

                bool fits = IsOnePassFor(entry.Ops, signature);
                if (fits || !shifted)
                {
                    entry.Used = true;
                    return fits ? entry : null;
                }
            }
            return null;
        }

        /// <summary>
        /// Whether the one-pass signature announces the signature: by the same key, and with its salt for version 6
        /// or its hash algorithm and type before.
        /// </summary>
        private static bool IsOnePassFor(PgpOnePassSignature ops, PgpSignature signature)
        {
            if (ops.KeyId != signature.KeyId)
                return false;
            if (signature.Version == 6)
                return ops.GetSalt().SequenceEqual(signature.GetSalt());

            return ops.HashAlgorithm == signature.HashAlgorithm && ops.SignatureType == signature.SignatureType;
        }

        /// <summary>One OpenPGP Message per input: after it, only markers, padding and non-critical packets.</summary>
        private static void RequireEndOfMessage(PgpObjectFactory factory)
        {
            PgpObject trailing = NextMessageObject(factory);
            if (trailing != null)
                throw new SopException(ExitCode.BadData, "unexpected " + Describe(trailing) + " after the message");
        }

        /// <summary>The next object of a message, skipping markers, padding and non-critical unknown packets.</summary>
        private static PgpObject NextMessageObject(PgpObjectFactory factory)
        {
            while (true)
            {
                PgpObject obj = factory.NextPgpObject();
                switch (obj)
                {
                case PgpMarker _:
                case PgpPadding _:
                    continue;
                case PgpUnknown unknown when !unknown.IsCritical:
                    continue;
                // one-pass signatures of unknown versions are dropped by the parser and must be ignored, not
                // rejected (RFC 9580 5.2.5), but are counted; signatures of unknown versions leave an empty list,
                // which still closes one-pass signatures
                case PgpOnePassSignatureList opsList when opsList.Count == 0 && opsList.UnsupportedCount == 0:
                    continue;
                case PgpExperimental experimental when (int)experimental.PacketTag >= 40:
                    continue;
                default:
                    return obj;
                }
            }
        }

        private static string Describe(PgpObject obj)
        {
            switch (obj)
            {
            case PgpUnknown unknown:
                return "critical packet " + (int)unknown.PacketTag;
            case PgpExperimental experimental:
                return "packet " + (int)experimental.PacketTag;
            default:
                return obj.GetType().Name;
            }
        }

        // The SOP mode follows the signature type, not the literal data format
        private static string ModeOf(PgpSignature signature) =>
            signature.SignatureType == PgpSignature.CanonicalTextDocument ? "text" : "binary";

        private static bool TryVerifyData(PgpSignature signature, PgpPublicKey key, byte[] data)
        {
            try
            {
                signature.InitVerify(key);
                signature.Update(data);
                return signature.Verify();
            }
            catch (Exception e) when (e is PgpException || e is IOException)
            {
                return false;
            }
        }

        private static bool TryInitVerify(PgpOnePassSignature ops, PgpPublicKey key)
        {
            try
            {
                ops.InitVerify(key);
                return true;
            }
            catch (PgpException)
            {
                return false;
            }
        }

        private static bool TryVerify(PgpOnePassSignature ops, PgpSignature signature)
        {
            try
            {
                return ops.Verify(signature);
            }
            catch (Exception e) when (e is PgpException || e is IOException)
            {
                return false;
            }
        }

        /// <summary>
        /// Whether a signature is valid in its context (RFC 9580 5.2.3.36): one that names intended recipients only in
        /// an encrypted message for one of them. The recipient fingerprints are null outside an encrypted message.
        /// </summary>
        private static bool NamesRecipient(PgpSignature signature, List<byte[]> recipientFingerprints)
        {
            PgpSignatureSubpacketVector hashed = signature.GetHashedSubPackets();
            IntendedRecipientFingerprint[] intended = hashed?.GetIntendedRecipientFingerprints();
            if (intended == null || intended.Length == 0)
                return true;
            if (recipientFingerprints == null)
                return false;

            return intended.Any(r => recipientFingerprints.Any(f => r.GetFingerprint().SequenceEqual(f)));
        }

        private static string VerificationLine(PgpSignature signature, PgpPublicKey key, PgpPublicKeyRing cert,
            string mode)
        {
            return string.Format("{0:yyyy-MM-ddTHH:mm:ssZ} {1} {2} mode:{3}", signature.CreationTime.ToUniversalTime(),
                Hex.ToHexString(key.GetFingerprint()).ToUpperInvariant(),
                Hex.ToHexString(cert.GetPublicKey().GetFingerprint()).ToUpperInvariant(), mode);
        }

        // ---------------------------------------------------------------- sign, verify

        private static int Sign(Arguments args)
        {
            bool armor = !args.Flag("--no-armor");
            bool text = ParseAs(args);
            List<char[]> passwords = args.Options("--with-key-password").Select(ReadPassword).ToList();
            List<string> keyFiles = args.RemainingPositionals();
            args.Finish();

            if (keyFiles.Count == 0)
                throw new SopException(ExitCode.MissingArg, "no keys given");

            var signers = keyFiles.SelectMany(f => ReadSecretRings(ReadFile(f)))
                .Select(ring => SigningKey(ring, passwords)).ToList();
            byte[] data = ReadStdin();

            WriteOutput(armor, outStr =>
            {
                foreach (PgpPrivateKey signer in signers)
                {
                    var sigGen = new PgpSignatureGenerator(signer.PublicKeyPacket.Algorithm, HashAlgorithmTag.Sha512);
                    sigGen.InitSign(text ? PgpSignature.CanonicalTextDocument : PgpSignature.BinaryDocument, signer);
                    sigGen.Update(data);
                    sigGen.Generate().Encode(outStr);
                }
            });
            return ExitCode.Ok;
        }

        private static int Verify(Arguments args)
        {
            DateTime? notBefore = ParseDate(args.Option("--not-before"));
            DateTime? notAfter = ParseDate(args.Option("--not-after"));
            string signaturesFile = args.RequirePositional("signatures");
            List<string> certFiles = args.RemainingPositionals();
            args.Finish();

            if (certFiles.Count == 0)
                throw new SopException(ExitCode.MissingArg, "no certificates given");

            var certs = certFiles.SelectMany(f => ReadPublicRings(ReadFile(f))).ToList();
            byte[] data = ReadStdin();
            var window = new SignatureWindow(notBefore, notAfter);

            var verifications = new List<string>();
            var factory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(
                new MemoryStream(ReadFile(signaturesFile), false)));
            foreach (PgpSignature signature in ReadSignatureSequence(factory))
            {
                VerifyDetached(signature, certs, data, window, verifications);
            }

            // at least one signature has to verify (RFC 9980 3.3): the others may be malformed
            if (verifications.Count == 0)
                throw new SopException(ExitCode.NoSignature, "no valid signature");

            foreach (string line in verifications)
            {
                Console.WriteLine(line);
            }
            return ExitCode.Ok;
        }

        /// <summary>
        /// The signatures of a sequence of signatures (RFC 9580 10.4): markers, padding and non-critical unknown
        /// packets are skipped, anything else rejects it (4.3).
        /// </summary>
        private static List<PgpSignature> ReadSignatureSequence(PgpObjectFactory factory)
        {
            var signatures = new List<PgpSignature>();
            PgpObject obj;
            while ((obj = NextMessageObject(factory)) != null)
            {
                if (!(obj is PgpSignatureList sigList))
                    throw new SopException(ExitCode.BadData, "unexpected " + Describe(obj) + " in the signatures");

                AddAll(signatures, sigList);
            }
            return signatures;
        }

        private static void VerifyDetached(PgpSignature signature, List<PgpPublicKeyRing> certs, byte[] data,
            SignatureWindow window, List<string> verifications)
        {
            if (!window.Contains(signature))
                return;

            // only signatures over documents that have not expired, by keys that sign for their certificate when the
            // signature is made, and outside an encrypted message only signatures without intended recipients
            if (!IsValidDocumentSignature(signature) || !NamesRecipient(signature, null))
                return;

            foreach (var cert in certs)
            {
                PgpPublicKey key = cert.GetPublicKey(signature.KeyId);
                if (key == null || !CanSignFor(cert, key, signature.CreationTime))
                    continue;

                try
                {
                    signature.InitVerify(key);
                    signature.Update(data);
                    if (signature.Verify())
                    {
                        string mode = signature.SignatureType == PgpSignature.CanonicalTextDocument
                            ? "text" : "binary";
                        verifications.Add(VerificationLine(signature, key, cert, mode));
                    }
                }
                catch (Exception e) when (e is PgpException || e is IOException)
                {
                }
            }
        }

        // ---------------------------------------------------------------- armor, dearmor

        private static int Armor(Arguments args)
        {
            args.Finish();
            byte[] data = ReadStdin();
            if (IsArmored(data))
            {
                WriteRaw(data);
                return ExitCode.Ok;
            }

            WriteOutput(true, outStr => outStr.Write(data, 0, data.Length));
            return ExitCode.Ok;
        }

        private static int Dearmor(Arguments args)
        {
            args.Finish();
            byte[] data = ReadStdin();
            WriteRaw(IsArmored(data) ? Streams.ReadAll(new ArmoredInputStream(new MemoryStream(data, false))) : data);
            return ExitCode.Ok;
        }

        // ---------------------------------------------------------------- helpers

        /// <summary>The value of a <c>--not-before</c> or <c>--not-after</c> option: a date, "now" or "-".</summary>
        private static DateTime? ParseDate(string value)
        {
            if (value == null || value == "-")
                return null;
            if (value == "now")
                return DateTime.UtcNow;

            if (!DateTime.TryParse(value, System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal,
                out DateTime parsed))
            {
                throw new SopException(ExitCode.UnsupportedOption, "cannot parse date: " + value);
            }
            return parsed;
        }

        private static bool ParseAs(Arguments args)
        {
            string asValue = args.Option("--as") ?? "binary";
            switch (asValue)
            {
            case "binary":
                return false;
            case "text":
                return true;
            default:
                throw new SopException(ExitCode.UnsupportedOption, "unsupported --as " + asValue);
            }
        }

        private static List<PgpSecretKeyRing> ReadSecretRings(byte[] data) =>
            ReadObjects(data).OfType<PgpSecretKeyRing>().ToList();

        private static List<PgpPublicKeyRing> ReadPublicRings(byte[] data)
        {
            var rings = new List<PgpPublicKeyRing>();
            foreach (PgpObject obj in ReadObjects(data))
            {
                if (obj is PgpPublicKeyRing publicRing)
                {
                    rings.Add(publicRing);
                }
                else if (obj is PgpSecretKeyRing secretRing)
                {
                    var bOut = new MemoryStream();
                    foreach (PgpPublicKey publicKey in secretRing.GetPublicKeys())
                    {
                        publicKey.Encode(bOut);
                    }
                    rings.Add(new PgpPublicKeyRing(bOut.ToArray()));
                }
            }
            return rings;
        }

        private static List<PgpObject> ReadObjects(byte[] data)
        {
            try
            {
                var objects = new List<PgpObject>();
                foreach (byte[] block in SplitArmorBlocks(data))
                {
                    var factory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(new MemoryStream(block, false)));
                    objects.AddRange(factory.AllPgpObjects());
                }
                return objects;
            }
            catch (Exception e)
            {
                throw new SopException(ExitCode.BadData, "bad data: " + e.Message);
            }
        }

        /// <summary>Split concatenated ASCII-armored blocks; binary data is returned as a single block.</summary>
        private static IEnumerable<byte[]> SplitArmorBlocks(byte[] data)
        {
            if (!IsArmored(data))
                return new[]{ data };

            string text = Encoding.ASCII.GetString(data);
            var blocks = new List<byte[]>();
            int start = text.IndexOf("-----BEGIN PGP", StringComparison.Ordinal);
            while (start >= 0)
            {
                int end = text.IndexOf("-----END PGP", start, StringComparison.Ordinal);
                if (end < 0)
                    throw new SopException(ExitCode.BadData, "unterminated armor");

                int lineEnd = text.IndexOf('\n', end);
                lineEnd = lineEnd < 0 ? text.Length : lineEnd + 1;
                blocks.Add(Encoding.ASCII.GetBytes(text.Substring(start, lineEnd - start)));
                start = text.IndexOf("-----BEGIN PGP", lineEnd, StringComparison.Ordinal);
            }
            return blocks;
        }

        private static char[] ReadPassword(string file)
        {
            string password = Encoding.UTF8.GetString(ReadFile(file));
            return password.TrimEnd('\r', '\n').ToCharArray();
        }

        private static byte[] ReadFile(string file)
        {
            if (file.StartsWith("@"))
                throw new SopException(ExitCode.UnsupportedSpecialPrefix, "unsupported special prefix: " + file);
            if (!File.Exists(file))
                throw new SopException(ExitCode.MissingInput, "missing input: " + file);

            return File.ReadAllBytes(file);
        }

        private static byte[] ReadStdin()
        {
            using (Stream stdin = Console.OpenStandardInput())
            {
                return Streams.ReadAll(stdin);
            }
        }

        private static bool IsArmored(byte[] data) =>
            Encoding.ASCII.GetString(data, 0, System.Math.Min(data.Length, 64)).Contains("-----BEGIN PGP");

        private static void WriteOutput(bool armor, Action<Stream> write)
        {
            var bOut = new MemoryStream();
            if (armor)
            {
                using (var armored = new ArmoredOutputStream(bOut))
                {
                    write(armored);
                }
            }
            else
            {
                write(bOut);
            }
            WriteRaw(bOut.ToArray());
        }

        private static void WriteRaw(byte[] data)
        {
            using (Stream stdout = Console.OpenStandardOutput())
            {
                stdout.Write(data, 0, data.Length);
            }
        }
    }

    /// <summary>
    /// Minimal SOP argument parsing: <c>subcommand [--flag] [--option=value | --option value] args</c>.
    /// </summary>
    internal sealed class Arguments
    {
        private static readonly HashSet<string> ValueOptions = new HashSet<string>{
            "--as", "--profile", "--sign-with", "--with-key-password", "--verify-with", "--verifications-out",
            "--session-key-out", "--with-session-key", "--with-password", "--not-before", "--not-after",
            "--verify-not-before", "--verify-not-after",
        };

        private readonly List<KeyValuePair<string, string>> m_options = new List<KeyValuePair<string, string>>();
        private readonly List<string> m_positionals = new List<string>();
        private readonly HashSet<string> m_used = new HashSet<string>();

        internal Arguments(string[] args)
        {
            if (args.Length == 0)
                throw new SopException(ExitCode.MissingArg, "missing subcommand");

            Subcommand = args[0];
            for (int i = 1; i < args.Length; ++i)
            {
                string arg = args[i];
                if (!arg.StartsWith("--"))
                {
                    m_positionals.Add(arg);
                    continue;
                }

                int eq = arg.IndexOf('=');
                string name = eq < 0 ? arg : arg.Substring(0, eq);
                string value = eq < 0 ? null : arg.Substring(eq + 1);
                if (value == null && ValueOptions.Contains(name))
                {
                    if (i + 1 >= args.Length)
                        throw new SopException(ExitCode.MissingArg, "missing value for " + name);

                    value = args[++i];
                }
                m_options.Add(new KeyValuePair<string, string>(name, value));
            }
        }

        internal string Subcommand { get; }

        internal bool Flag(string name)
        {
            m_used.Add(name);
            return m_options.Any(o => o.Key == name);
        }

        internal string Option(string name) => Options(name).LastOrDefault();

        internal List<string> Options(string name)
        {
            m_used.Add(name);
            return m_options.Where(o => o.Key == name).Select(o => o.Value).ToList();
        }

        internal string RequirePositional(string what)
        {
            if (m_positionals.Count == 0)
                throw new SopException(ExitCode.MissingArg, "missing " + what);

            string value = m_positionals[0];
            m_positionals.RemoveAt(0);
            return value;
        }

        internal List<string> RemainingPositionals()
        {
            var remaining = new List<string>(m_positionals);
            m_positionals.Clear();
            return remaining;
        }

        /// <summary>Fail on any option the subcommand did not consume.</summary>
        internal void Finish()
        {
            foreach (var option in m_options)
            {
                if (!m_used.Contains(option.Key) && option.Key != "--debug")
                    throw new SopException(ExitCode.UnsupportedOption, "unsupported option: " + option.Key);
            }
            if (m_positionals.Count > 0)
                throw new SopException(ExitCode.UnsupportedOption, "unexpected argument: " + m_positionals[0]);
        }
    }
}
