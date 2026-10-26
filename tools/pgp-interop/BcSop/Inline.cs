using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Tools.PgpInterop
{
    internal static partial class Program
    {
        private const string ClearTextHeader = "-----BEGIN PGP SIGNED MESSAGE-----";

        // ---------------------------------------------------------------- inline-sign

        private static int InlineSign(Arguments args)
        {
            bool armor = !args.Flag("--no-armor");
            string mode = args.Option("--as") ?? "binary";
            List<char[]> passwords = args.Options("--with-key-password").Select(ReadPassword).ToList();
            List<string> keyFiles = args.RemainingPositionals();
            args.Finish();

            if (mode != "binary" && mode != "text" && mode != "clearsigned")
                throw new SopException(ExitCode.UnsupportedOption, "unsupported --as " + mode);
            if (keyFiles.Count == 0)
                throw new SopException(ExitCode.MissingArg, "no keys given");
            if (mode == "clearsigned" && !armor)
                throw new SopException(ExitCode.UnsupportedOption, "clearsigned output is always armored");

            var signers = keyFiles.SelectMany(f => ReadSecretRings(ReadFile(f)))
                .Select(ring => SigningKey(ring, passwords)).ToList();
            byte[] content = ReadStdin();

            if (mode == "clearsigned")
            {
                WriteRaw(ClearSign(signers, content));
                return ExitCode.Ok;
            }

            WriteOutput(armor, outStr => WriteSignedContent(outStr, signers, new List<PgpPublicKey>(), content,
                mode == "text"));
            return ExitCode.Ok;
        }

        /// <summary>
        /// The cleartext signature framework (RFC 9580 7). The text is signed with the line endings as CRLF and
        /// without trailing white space; a Hash header is only written for version 4 keys, since version 6
        /// signatures do not use it.
        /// </summary>
        private static byte[] ClearSign(List<PgpPrivateKey> signers, byte[] content)
        {
            // A final line ending belongs to the text (an empty last line); the framework adds its own line ending
            // in front of the signature (RFC 9580 7.1), which the verifier removes again.
            string text = Encoding.UTF8.GetString(content).Replace("\r\n", "\n");
            string[] lines = text.Split('\n');

            var sigGens = new List<PgpSignatureGenerator>();
            foreach (PgpPrivateKey signer in signers)
            {
                var sigGen = new PgpSignatureGenerator(signer.PublicKeyPacket.Algorithm, HashAlgorithmTag.Sha512);
                sigGen.InitSign(PgpSignature.CanonicalTextDocument, signer);
                sigGens.Add(sigGen);
            }

            var bOut = new MemoryStream();
            using (var armored = new ArmoredOutputStream(bOut))
            {
                if (signers.All(s => s.PublicKeyPacket.Version == PublicKeyPacket.Version6))
                {
                    armored.BeginClearText();
                }
                else
                {
                    armored.BeginClearText(HashAlgorithmTag.Sha512);
                }

                for (int i = 0; i < lines.Length; ++i)
                {
                    string stripped = lines[i].TrimEnd(' ', '\t', '\r');
                    if (i > 0)
                    {
                        foreach (var sigGen in sigGens)
                        {
                            sigGen.Update((byte)'\r');
                            sigGen.Update((byte)'\n');
                        }
                        armored.WriteByte((byte)'\n');
                    }
                    byte[] signedLine = Encoding.UTF8.GetBytes(stripped);
                    foreach (var sigGen in sigGens)
                    {
                        sigGen.Update(signedLine);
                    }
                    byte[] line = Encoding.UTF8.GetBytes(lines[i].TrimEnd('\r'));
                    armored.Write(line, 0, line.Length);
                }

                // the line ending of the last line is not part of the signed text
                armored.WriteByte((byte)'\n');
                armored.EndClearText();

                var pOut = new BcpgOutputStream(armored);
                foreach (var sigGen in sigGens)
                {
                    sigGen.Generate().Encode(pOut);
                }
            }
            return bOut.ToArray();
        }

        // ---------------------------------------------------------------- inline-verify

        private static int InlineVerify(Arguments args)
        {
            DateTime? notBefore = ParseDate(args.Option("--not-before"));
            DateTime? notAfter = ParseDate(args.Option("--not-after"));
            string verificationsOut = args.Option("--verifications-out");
            List<string> certFiles = args.RemainingPositionals();
            args.Finish();

            if (verificationsOut != null && File.Exists(verificationsOut))
                throw new SopException(ExitCode.OutputExists, "output exists: " + verificationsOut);
            if (certFiles.Count == 0)
                throw new SopException(ExitCode.MissingArg, "no certificates given");

            var certs = certFiles.SelectMany(f => ReadPublicRings(ReadFile(f))).ToList();
            byte[] message = ReadStdin();
            var window = new SignatureWindow(notBefore, notAfter);

            Content content;
            try
            {
                content = Encoding.ASCII.GetString(message, 0, System.Math.Min(message.Length, 64))
                        .TrimStart().StartsWith(ClearTextHeader)
                    ? VerifyClearText(message, certs, window)
                    : ReadContent(PgpUtilities.GetDecoderStream(new MemoryStream(message, false)), certs, window,
                        null);
            }
            catch (SopException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new SopException(ExitCode.BadData, "bad data: " + e.Message);
            }

            if (content.Verifications.Count == 0)
                throw new SopException(ExitCode.NoSignature, "no valid signature");

            if (verificationsOut != null)
            {
                File.WriteAllText(verificationsOut, string.Concat(content.Verifications.Select(v => v + "\n")));
            }
            WriteRaw(content.Data);
            return ExitCode.Ok;
        }

        private static Content VerifyClearText(byte[] message, List<PgpPublicKeyRing> certs, SignatureWindow window)
        {
            var armored = new ArmoredInputStream(new MemoryStream(message, false));
            var text = new MemoryStream();
            int ch;
            while ((ch = armored.ReadByte()) >= 0 && armored.IsClearText())
            {
                text.WriteByte((byte)ch);
            }

            // The line ending in front of the signature header is not part of the text (RFC 9580 7.1)
            string received = Encoding.UTF8.GetString(text.ToArray());
            if (received.EndsWith("\r\n"))
            {
                received = received.Substring(0, received.Length - 2);
            }
            else if (received.EndsWith("\n"))
            {
                received = received.Substring(0, received.Length - 1);
            }
            string clearText = received.Replace("\r\n", "\n");
            string canonical = string.Join("\r\n", clearText.Split('\n').Select(l => l.TrimEnd(' ', '\t', '\r')));
            byte[] signedText = Encoding.UTF8.GetBytes(canonical);

            // the text as it was transmitted, without the line ending that belongs to the framework
            var content = new Content{ Data = Encoding.UTF8.GetBytes(received) };
            List<PgpSignature> signatures;
            try
            {
                signatures = ReadSignatureSequence(new PgpObjectFactory(armored));
            }
            catch (ArmoredInputException)
            {
                // RFC 9580 7.1: with another armor header than a well-formed Hash header, no signature counts
                return content;
            }

            // RFC 9580 7.1: a cleartext signature is a text signature (5.2.1.2)
            foreach (PgpSignature signature in signatures)
            {
                if (signature.SignatureType == PgpSignature.CanonicalTextDocument)
                {
                    VerifyDetached(signature, certs, signedText, window, content.Verifications);
                }
            }
            return content;
        }
    }
}
