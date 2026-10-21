using System.Security.Cryptography;
using System.Text;
using Lumen.Core.Detection;
using Lumen.Core.Scanning;

namespace Lumen.Core.Tests;

/// <summary>
/// The entropy rule measures how evenly the bytes of a file are spread. For a PNG, a
/// video or a ZIP that is not a finding, it is a fact about the format.
///
/// These tests exist because the rule once reported every screenshot and every
/// archive on the machine, which is exactly how a security tool teaches people to
/// ignore it.
/// </summary>
public sealed class EntropyMediaTests
{
    [Fact]
    public void A_png_with_even_bytes_is_not_reported()
    {
        var detector = new EntropyDetector();
        var probe = FileProbe.FromBytes("holiday.png", RandomBytes(64 * 1024));

        var findings = detector.Inspect(probe, CancellationToken.None);

        Assert.DoesNotContain(findings, finding => finding.RuleId == "entropy.high-entropy-file");
    }

    [Fact]
    public void A_video_or_an_archive_is_not_reported()
    {
        var detector = new EntropyDetector();

        foreach (var name in new[] { "clip.mp4", "photos.zip", "report.pdf", "song.mp3", "slides.pptx" })
        {
            var probe = FileProbe.FromBytes(name, RandomBytes(64 * 1024));
            var findings = detector.Inspect(probe, CancellationToken.None);

            Assert.DoesNotContain(
                findings,
                finding => finding.RuleId == "entropy.high-entropy-file");
        }
    }

    [Fact]
    public void An_unknown_extension_with_even_bytes_is_still_reported()
    {
        var detector = new EntropyDetector();
        var probe = FileProbe.FromBytes("payload.bin", RandomBytes(64 * 1024));

        var findings = detector.Inspect(probe, CancellationToken.None);

        Assert.Contains(findings, finding => finding.RuleId == "entropy.high-entropy-file");
    }

    [Fact]
    public void A_text_file_with_a_packed_tail_is_still_reported()
    {
        var detector = new EntropyDetector();

        var text = new string('a', 4096);
        var tail = RandomBytes(8192);
        var bytes = new byte[text.Length + tail.Length];
        Encoding.ASCII.GetBytes(text).CopyTo(bytes, 0);
        tail.CopyTo(bytes, text.Length);

        var probe = FileProbe.FromBytes("notes.txt", bytes);
        var findings = detector.Inspect(probe, CancellationToken.None);

        Assert.Contains(findings, finding => finding.RuleId == "entropy.encrypted-tail");
    }

    private static byte[] RandomBytes(int count)
    {
        var bytes = new byte[count];
        RandomNumberGenerator.Fill(bytes);
        return bytes;
    }
}
