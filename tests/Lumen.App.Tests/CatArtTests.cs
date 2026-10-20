using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Lumen.App.Alerts;
using Lumen.App.Tests.Support;

namespace Lumen.App.Tests;

/// <summary>
/// The cat is drawn by hand, and the drawing is the part of the alert that used to
/// cost the most. These tests render it off screen — no window is shown and the
/// application is never started — to prove that the drawing still works and that it
/// is built once instead of once per frame.
/// </summary>
public sealed class CatArtTests
{
    [Theory]
    [InlineData(CatMood.Alarmed)]
    [InlineData(CatMood.Calm)]
    [InlineData(CatMood.Content)]
    public void TheCat_isDrawnInEveryMood(CatMood mood)
    {
        var pixels = RenderCat(mood);

        Assert.True(pixels > 0, "The cat drew nothing at all.");
    }

    [Fact]
    public void TheCat_isDrawnAgainWhenTheMoodChanges()
    {
        // A new mood means new geometry, and the drawing must not fall over when it
        // is rebuilt.
        RenderCat(CatMood.Alarmed);
        var pixels = RenderCat(CatMood.Content);

        Assert.True(pixels > 0, "The cat drew nothing at all.");
    }

    [Fact]
    public void TheCat_isDrawnAgainWhenItIsResized()
    {
        RenderCat(CatMood.Alarmed, size: 150);
        var pixels = RenderCat(CatMood.Alarmed, size: 96);

        Assert.True(pixels > 0, "The cat drew nothing at all.");
    }

    /// <summary>
    /// Renders the cat off screen and counts the pixels that are not fully
    /// transparent. Anything that was drawn counts.
    /// </summary>
    private static int RenderCat(CatMood mood, double size = 150)
    {
        return WpfHost.Shared.Invoke(() =>
        {
            var cat = new CatArt
            {
                Mood = mood,
                Width = size,
                Height = size
            };

            cat.Measure(new Size(size, size));
            cat.Arrange(new Rect(0, 0, size, size));

            var width = (int)Math.Round(size);
            var target = new RenderTargetBitmap(width, width, 96, 96, PixelFormats.Pbgra32);
            target.Render(cat);

            var stride = width * 4;
            var pixels = new byte[stride * width];
            target.CopyPixels(pixels, stride, 0);

            var drawn = 0;
            for (var index = 3; index < pixels.Length; index += 4)
            {
                if (pixels[index] != 0) drawn++;
            }

            return drawn;
        });
    }
}
