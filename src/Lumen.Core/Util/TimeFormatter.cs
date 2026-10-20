using System.Globalization;

namespace Lumen.Core.Util;

public static class TimeFormatter
{
    public static string Duration(TimeSpan duration)
    {
        if (duration < TimeSpan.Zero) duration = TimeSpan.Zero;
        if (duration.TotalSeconds < 1) return "< 1s";
        if (duration.TotalHours >= 1)
            return string.Create(CultureInfo.InvariantCulture, $"{(int)duration.TotalHours}h {duration.Minutes}m");
        if (duration.TotalMinutes >= 1)
            return string.Create(CultureInfo.InvariantCulture, $"{(int)duration.TotalMinutes}m {duration.Seconds}s");
        return string.Create(CultureInfo.InvariantCulture, $"{(int)duration.TotalSeconds}s");
    }

    public static string Relative(DateTimeOffset when, DateTimeOffset now)
    {
        var delta = now - when;
        if (delta < TimeSpan.Zero) delta = TimeSpan.Zero;

        if (delta.TotalSeconds < 45) return "just now";
        if (delta.TotalMinutes < 60)
        {
            var minutes = Math.Max(1, (int)delta.TotalMinutes);
            return minutes == 1 ? "1 minute ago" : $"{minutes} minutes ago";
        }

        if (delta.TotalHours < 24)
        {
            var hours = Math.Max(1, (int)delta.TotalHours);
            return hours == 1 ? "1 hour ago" : $"{hours} hours ago";
        }

        var localWhen = when.ToLocalTime();
        var localNow = now.ToLocalTime();
        if (localWhen.Date == localNow.Date.AddDays(-1)) return "yesterday";
        if (delta.TotalDays < 7) return $"{(int)delta.TotalDays} days ago";
        return localWhen.ToString("MMM d, yyyy", CultureInfo.CurrentCulture);
    }

    public static string DateTime(DateTimeOffset when) =>
        when.ToLocalTime().ToString("MMM d, yyyy \u00B7 h:mm tt", CultureInfo.CurrentCulture);
}
