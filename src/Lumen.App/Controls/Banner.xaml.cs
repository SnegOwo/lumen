using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using Lumen.App.Dialogs;

namespace Lumen.App.Controls;

public partial class Banner : UserControl
{
    public static readonly DependencyProperty TitleProperty = DependencyProperty.Register(
        nameof(Title), typeof(string), typeof(Banner), new PropertyMetadata(string.Empty));

    public static readonly DependencyProperty MessageProperty = DependencyProperty.Register(
        nameof(Message), typeof(string), typeof(Banner), new PropertyMetadata(string.Empty));

    public static readonly DependencyProperty SeverityProperty = DependencyProperty.Register(
        nameof(Severity), typeof(MessageSeverity), typeof(Banner), new PropertyMetadata(MessageSeverity.Info));

    public static readonly DependencyProperty ShowCloseProperty = DependencyProperty.Register(
        nameof(ShowClose), typeof(bool), typeof(Banner), new PropertyMetadata(false));

    public static readonly DependencyProperty CloseCommandProperty = DependencyProperty.Register(
        nameof(CloseCommand), typeof(ICommand), typeof(Banner), new PropertyMetadata(null));

    public Banner()
    {
        InitializeComponent();
    }

    public string Title
    {
        get => (string)GetValue(TitleProperty);
        set => SetValue(TitleProperty, value);
    }

    public string Message
    {
        get => (string)GetValue(MessageProperty);
        set => SetValue(MessageProperty, value);
    }

    public MessageSeverity Severity
    {
        get => (MessageSeverity)GetValue(SeverityProperty);
        set => SetValue(SeverityProperty, value);
    }

    public bool ShowClose
    {
        get => (bool)GetValue(ShowCloseProperty);
        set => SetValue(ShowCloseProperty, value);
    }

    public ICommand? CloseCommand
    {
        get => (ICommand?)GetValue(CloseCommandProperty);
        set => SetValue(CloseCommandProperty, value);
    }
}
