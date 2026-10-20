using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;

namespace Lumen.Core.Storage;

/// <summary>
/// The single JSON contract used for every file Lumen writes. The options are frozen
/// after construction so a caller cannot change the format of a file another part of the
/// application is about to read.
/// </summary>
public static class JsonDefaults
{
    /// <summary>
    /// Shared serializer options. The instance is read-only; attempting to modify it
    /// throws instead of silently changing how data is written.
    /// </summary>
    public static JsonSerializerOptions Options { get; } = Create();

    private static JsonSerializerOptions Create()
    {
        var options = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            PropertyNameCaseInsensitive = true,
            WriteIndented = true,
            MaxDepth = 32,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };
        options.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.CamelCase));

        // The resolver has to be named before the options can be frozen.
        options.TypeInfoResolver = new DefaultJsonTypeInfoResolver();
        options.MakeReadOnly();
        return options;
    }
}
