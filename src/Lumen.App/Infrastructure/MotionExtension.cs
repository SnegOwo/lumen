using System;
using System.Windows;
using System.Windows.Markup;

namespace Lumen.App.Infrastructure;

/// <summary>
/// Hands a motion token to WPF as a <see cref="Duration"/>.
/// </summary>
/// <remarks>
/// The motion tokens in <c>Themes/Tokens.xaml</c> are <see cref="TimeSpan"/>
/// values, because that is the type code can use directly. WPF, on the other
/// hand, wants a <see cref="Duration"/> inside a storyboard and cannot convert
/// a <see cref="TimeSpan"/> that was handed to it as an already evaluated
/// resource. This extension bridges the two:
/// <code>
/// &lt;DoubleAnimation Duration="{infra:Motion Motion.Fast}" /&gt;
/// </code>
/// When the token cannot be found the extension falls back to a sane default
/// instead of throwing, so a missing token can never stop a template from
/// loading.
/// </remarks>
[MarkupExtensionReturnType(typeof(Duration))]
public sealed class MotionExtension : MarkupExtension
{
    private static readonly Duration Fallback = new(TimeSpan.FromMilliseconds(180));

    public MotionExtension()
    {
    }

    public MotionExtension(string resourceKey)
    {
        ResourceKey = resourceKey;
    }

    /// <summary>The key of the motion token, for example <c>Motion.Fast</c>.</summary>
    public string? ResourceKey { get; set; }

    public override object ProvideValue(IServiceProvider serviceProvider)
    {
        if (string.IsNullOrWhiteSpace(ResourceKey))
        {
            throw new ArgumentException("A motion token key is required, for example Motion.Fast.", nameof(ResourceKey));
        }

        var value = Application.Current?.TryFindResource(ResourceKey);
        return value is TimeSpan span ? new Duration(span) : Fallback;
    }
}
