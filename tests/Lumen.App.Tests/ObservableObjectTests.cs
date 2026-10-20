using System.ComponentModel;
using Lumen.App.Infrastructure;

namespace Lumen.App.Tests;

public sealed class ObservableObjectTests
{
    private sealed class Probe : ObservableObject
    {
        private string _name = "initial";
        private int _count;

        public string Name
        {
            get => _name;
            set => SetProperty(ref _name, value);
        }

        public int Count
        {
            get => _count;
            set => SetProperty(ref _count, value);
        }

        public bool SetName(string value) => SetProperty(ref _name, value);

        public bool SetCount(int value) => SetProperty(ref _count, value);

        public void RaiseOne(string propertyName) => OnPropertyChanged(propertyName);

        public void RaiseMany(params string[] propertyNames) => OnPropertyChanged(propertyNames);

        public void RaiseCaller() => OnPropertyChanged();
    }

    private static (Probe Probe, List<string?> Notifications) CreateProbe()
    {
        var probe = new Probe();
        var notifications = new List<string?>();
        probe.PropertyChanged += (_, args) => notifications.Add(args.PropertyName);
        return (probe, notifications);
    }

    [Fact]
    public void SetProperty_unchangedValue_returnsFalseAndRaisesNothing()
    {
        var (probe, notifications) = CreateProbe();

        var changed = probe.SetName("initial");

        Assert.False(changed);
        Assert.Empty(notifications);
    }

    [Fact]
    public void SetProperty_changedValue_returnsTrue()
    {
        var (probe, _) = CreateProbe();

        var changed = probe.SetName("changed");

        Assert.True(changed);
    }

    [Fact]
    public void SetProperty_changedValue_raisesPropertyChangedWithTheCallerMemberName()
    {
        var (probe, notifications) = CreateProbe();

        probe.Name = "changed";

        Assert.Equal(new[] { "Name" }, notifications);
    }

    [Fact]
    public void SetProperty_changedValue_updatesTheStoredValue()
    {
        var (probe, _) = CreateProbe();

        probe.SetName("changed");

        Assert.Equal("changed", probe.Name);
    }

    [Fact]
    public void SetProperty_differentValueType_raisesPropertyChanged()
    {
        var (probe, notifications) = CreateProbe();

        probe.Count = 7;

        Assert.Equal(new[] { "Count" }, notifications);
        Assert.Equal(7, probe.Count);
    }

    [Fact]
    public void SetProperty_sameValueType_raisesNothing()
    {
        var (probe, notifications) = CreateProbe();

        probe.SetCount(0);

        Assert.Empty(notifications);
    }

    [Fact]
    public void OnPropertyChanged_withAName_raisesPropertyChangedWithThatName()
    {
        var (probe, notifications) = CreateProbe();

        probe.RaiseOne("Whatever");

        Assert.Equal(new[] { "Whatever" }, notifications);
    }

    [Fact]
    public void OnPropertyChanged_paramsOverload_raisesEverySuppliedName()
    {
        var (probe, notifications) = CreateProbe();

        probe.RaiseMany("First", "Second", "Third");

        Assert.Equal(new[] { "First", "Second", "Third" }, notifications);
    }

    [Fact]
    public void OnPropertyChanged_paramsOverload_withNoNames_raisesNothing()
    {
        var (probe, notifications) = CreateProbe();

        probe.RaiseMany();

        Assert.Empty(notifications);
    }

    [Fact]
    public void OnPropertyChanged_withoutAName_raisesPropertyChangedWithTheCallerMemberName()
    {
        var (probe, notifications) = CreateProbe();

        probe.RaiseCaller();

        Assert.Equal(new[] { "RaiseCaller" }, notifications);
    }

    [Fact]
    public void PropertyChanged_isRaisedWithTheSenderAndThePropertyName()
    {
        var probe = new Probe();
        PropertyChangedEventArgs? captured = null;
        object? sender = null;

        probe.PropertyChanged += (source, args) =>
        {
            sender = source;
            captured = args;
        };

        probe.Name = "changed";

        Assert.Same(probe, sender);
        Assert.NotNull(captured);
        Assert.Equal("Name", captured.PropertyName);
    }
}
