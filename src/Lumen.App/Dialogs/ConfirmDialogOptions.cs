namespace Lumen.App.Dialogs;

public enum MessageSeverity
{
    Info,
    Success,
    Warning,
    Danger
}

public sealed record ConfirmDialogOptions
{
    public required string Title { get; init; }
    public required string Message { get; init; }
    public string PrimaryText { get; init; } = "OK";
    public string CancelText { get; init; } = "Cancel";
    public bool ShowCancel { get; init; } = true;
    public bool IsDanger { get; init; }
    public string? Details { get; init; }
    public MessageSeverity Severity { get; init; } = MessageSeverity.Info;
}
