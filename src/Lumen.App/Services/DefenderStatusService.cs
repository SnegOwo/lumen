using System.Diagnostics;
using System.Globalization;
using Lumen.Core.Util;

namespace Lumen.App.Services;

public sealed record DefenderStatus(
    bool IsAvailable,
    bool AntivirusEnabled,
    bool RealTimeProtectionEnabled,
    string? SignatureVersion,
    DateTimeOffset? SignatureUpdatedUtc,
    string Message,
    DateTimeOffset CheckedUtc)
{
    public static DefenderStatus Unavailable(string message, DateTimeOffset now) =>
        new(false, false, false, null, null, message, now);

    public string SignatureText => string.IsNullOrWhiteSpace(SignatureVersion)
        ? "Signature version unavailable"
        : "Signatures " + SignatureVersion;

    public string UpdatedText => SignatureUpdatedUtc is null
        ? "Last update unavailable"
        : "Updated " + TimeFormatter.DateTime(SignatureUpdatedUtc.Value);
}

/// <summary>
/// Reads Microsoft Defender status without changing any setting. This is deliberately
/// read-only: Lumen never disables, configures or bypasses real-time protection.
/// </summary>
public sealed class DefenderStatusService
{
    private static readonly TimeSpan QueryTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan CacheDuration = TimeSpan.FromMinutes(2);
    private readonly Lumen.Core.Abstractions.IClock _clock;
    private readonly SemaphoreSlim _mutex = new(1, 1);
    private DefenderStatus? _cached;

    public DefenderStatusService(Lumen.Core.Abstractions.IClock clock)
    {
        _clock = clock;
    }

    public async Task<DefenderStatus> GetAsync(
        bool force = false,
        CancellationToken cancellationToken = default)
    {
        if (!force && _cached is not null && _clock.UtcNow - _cached.CheckedUtc < CacheDuration)
            return _cached;

        await _mutex.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!force && _cached is not null && _clock.UtcNow - _cached.CheckedUtc < CacheDuration)
                return _cached;

            _cached = await QueryAsync(cancellationToken).ConfigureAwait(false);
            return _cached;
        }
        finally
        {
            _mutex.Release();
        }
    }

    private async Task<DefenderStatus> QueryAsync(CancellationToken cancellationToken)
    {
        var now = _clock.UtcNow;
        var script = string.Join(
            "; ",
            "$ErrorActionPreference='Stop'",
            "$s=Get-MpComputerStatus",
            "'AMServiceEnabled='+$s.AMServiceEnabled",
            "'AntivirusEnabled='+$s.AntivirusEnabled",
            "'RealTimeProtectionEnabled='+$s.RealTimeProtectionEnabled",
            "'AntivirusSignatureVersion='+$s.AntivirusSignatureVersion",
            "'AntivirusSignatureLastUpdated='+$s.AntivirusSignatureLastUpdated.ToString('o')");

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = Path.Combine(
                    Environment.SystemDirectory,
                    "WindowsPowerShell",
                    "v1.0",
                    "powershell.exe"),
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            psi.ArgumentList.Add("-NoProfile");
            psi.ArgumentList.Add("-NonInteractive");
            psi.ArgumentList.Add("-ExecutionPolicy");
            psi.ArgumentList.Add("Bypass");
            psi.ArgumentList.Add("-Command");
            psi.ArgumentList.Add(script);

            using var process = new Process { StartInfo = psi };
            if (!process.Start())
                return DefenderStatus.Unavailable("Windows Security status could not be read.", now);

            var outputTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
            var errorTask = process.StandardError.ReadToEndAsync(cancellationToken);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(QueryTimeout);

            try
            {
                await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                TryKill(process);
                return DefenderStatus.Unavailable(
                    "Windows Security did not respond in time. Status is unavailable.",
                    now);
            }
            catch (OperationCanceledException)
            {
                TryKill(process);
                throw;
            }

            var output = await outputTask.ConfigureAwait(false);
            var error = await errorTask.ConfigureAwait(false);

            var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var line in output.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
            {
                var separator = line.IndexOf('=');
                if (separator <= 0) continue;
                values[line[..separator].Trim()] = line[(separator + 1)..].Trim();
            }

            if (values.Count == 0)
            {
                var detail = string.IsNullOrWhiteSpace(error) ? "No status was returned." : "Query failed.";
                return DefenderStatus.Unavailable(
                    "Windows Security status is unavailable. " + detail,
                    now);
            }

            var antivirus = ReadBool(values, "AntivirusEnabled");
            var realTime = ReadBool(values, "RealTimeProtectionEnabled");
            var signature = values.GetValueOrDefault("AntivirusSignatureVersion");

            DateTimeOffset? updated = null;
            if (values.TryGetValue("AntivirusSignatureLastUpdated", out var rawUpdated) &&
                DateTimeOffset.TryParse(
                    rawUpdated,
                    CultureInfo.InvariantCulture,
                    DateTimeStyles.RoundtripKind,
                    out var parsed))
            {
                updated = parsed;
            }

            var message = realTime
                ? "Real-time protection is on. Lumen reads this status only."
                : "Real-time protection reports as off. Open Windows Security to review it.";

            return new DefenderStatus(
                true,
                antivirus,
                realTime,
                string.IsNullOrWhiteSpace(signature) ? null : DisplayText.Sanitize(signature, 80),
                updated,
                message,
                now);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception)
        {
            return DefenderStatus.Unavailable(
                "Windows Security status is unavailable on this system. You can still open Windows Security.",
                now);
        }
    }

    private static bool ReadBool(IReadOnlyDictionary<string, string> values, string key) =>
        values.TryGetValue(key, out var raw) && bool.TryParse(raw, out var parsed) && parsed;

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
        }
        catch
        {
            // The process may have exited between the check and the kill.
        }
    }
}
