using System.Text;

namespace Lumen.App.Services;

public sealed record TestFileResult(bool Ok, string Message, IReadOnlyList<string> Created);

/// <summary>
/// Creates harmless test material for verifying detection, quarantine and restore. The EICAR
/// payload is assembled from character codes at runtime and written only on explicit request;
/// no raw test signature is stored in the repository or executable.
/// </summary>
public sealed class TestFileService
{
    private static readonly int[] EicarCodes =
    [
        88, 53, 79, 33, 80, 37, 64, 65, 80, 91, 52, 92, 80, 90, 88, 53, 52, 40, 80, 94,
        41, 55, 67, 67, 41, 55, 125, 36, 69, 73, 67, 65, 82, 45, 83, 84, 65, 78, 68, 65,
        82, 68, 45, 65, 78, 84, 73, 86, 73, 82, 85, 83, 45, 84, 69, 83, 84, 45, 70, 73,
        76, 69, 33, 36, 72, 43, 72, 42
    ];

    public TestFileResult CreateBenignSamples(string folder)
    {
        try
        {
            Directory.CreateDirectory(folder);
            var created = new List<string>();

            var readMe = Path.Combine(folder, "lumen-read-me.txt");
            File.WriteAllText(
                readMe,
                "These files were created by Lumen for safe, local scanner testing.\r\n" +
                "They contain plain text only and are not executable.\r\n" +
                "The double-extension sample exists solely to test Lumen's file-name heuristic.\r\n",
                new UTF8Encoding(false));
            created.Add(readMe);

            var note = Path.Combine(folder, "lumen-benign-note.txt");
            File.WriteAllText(
                note,
                "A harmless text file. Scanning this file should produce no findings.\r\n",
                new UTF8Encoding(false));
            created.Add(note);

            var doubleExtension = Path.Combine(folder, "lumen-report.pdf.exe");
            File.WriteAllText(
                doubleExtension,
                "This is plain text, not a Windows executable. Its name intentionally has two extensions.\r\n",
                new UTF8Encoding(false));
            created.Add(doubleExtension);

            return new TestFileResult(true, "Harmless test files were created.", created);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return new TestFileResult(false, "Test files could not be created: " + ex.Message, []);
        }
    }

    public TestFileResult CreateEicarSample(string folder)
    {
        try
        {
            Directory.CreateDirectory(folder);
            var path = Path.Combine(folder, "lumen-eicar-test-file.com");
            var bytes = new byte[EicarCodes.Length + 2];
            for (var index = 0; index < EicarCodes.Length; index++) bytes[index] = (byte)EicarCodes[index];
            bytes[^2] = 13;
            bytes[^1] = 10;

            File.WriteAllBytes(path, bytes);

            return new TestFileResult(
                true,
                "The EICAR test file was created. Microsoft Defender may quarantine it immediately. " +
                "EICAR is harmless and is not malware.",
                [path]);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return new TestFileResult(false, "The EICAR test file could not be created: " + ex.Message, []);
        }
    }
}
