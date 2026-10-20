using Lumen.Core.Abstractions;
using Lumen.Core.Models;
using Lumen.Core.Scanning;

namespace Lumen.Core.Detection;

/// <summary>
/// The EICAR test string is assembled from character codes at runtime. Keeping the raw
/// 68-byte sequence out of the source and executable prevents other antivirus products from
/// quarantining Lumen's own files while still allowing a genuine test-file detection.
/// EICAR is a harmless, industry-standard scanner test artifact, not malware.
/// </summary>
public sealed class EicarTestDetector : IScanDetector
{
    private const string Identifier = "test.eicar";

    private static readonly int[] Codes =
    [
        88, 53, 79, 33, 80, 37, 64, 65, 80, 91, 52, 92, 80, 90, 88, 53, 52, 40, 80, 94,
        41, 55, 67, 67, 41, 55, 125, 36, 69, 73, 67, 65, 82, 45, 83, 84, 65, 78, 68, 65,
        82, 68, 45, 65, 78, 84, 73, 86, 73, 82, 85, 83, 45, 84, 69, 83, 84, 45, 70, 73,
        76, 69, 33, 36, 72, 43, 72, 42
    ];

    private static readonly byte[] Signature = BuildSignature();

    public string Id => Identifier;
    public string Name => "EICAR test signature";
    public string Description =>
        "Detects the industry-standard EICAR test file, a harmless artifact used to verify scanner plumbing. It does not detect real malware.";
    public FindingCategory Category => FindingCategory.TestSignature;
    public Confidence Confidence => Confidence.Definitive;

    public IEnumerable<Finding> Inspect(FileProbe probe, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (probe.Content.Length < Signature.Length) return Array.Empty<Finding>();

        var offset = probe.Content.Span.IndexOf(Signature);
        if (offset < 0) return Array.Empty<Finding>();

        return
        [
            new Finding
            {
                RuleId = Identifier,
                Title = "EICAR antivirus test file",
                Category = FindingCategory.TestSignature,
                Confidence = Confidence.Definitive,
                Summary =
                    "The file contains the EICAR test string. This is a harmless industry-standard test artifact, not malware.",
                Detail = $"The 68-byte EICAR test string was found at byte offset {offset}.",
                Advice =
                    "No malware is present. Delete the file, or quarantine it to try Lumen's restore and delete controls."
            }
        ];
    }

    private static byte[] BuildSignature()
    {
        var bytes = new byte[Codes.Length];
        for (var index = 0; index < Codes.Length; index++) bytes[index] = (byte)Codes[index];
        return bytes;
    }
}
