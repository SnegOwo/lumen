using System.Windows.Input;

namespace Lumen.App.EasterEggs;

/// <summary>
/// Watches a sequence of key presses and reports when it has been typed in full.
/// It is how Lumen notices the Konami code without a keyboard hook: the window simply
/// asks this object whether the sequence has arrived.
/// </summary>
public sealed class KeySequenceWatcher
{
    private readonly Key[] _sequence;
    private readonly List<Key> _pressed = [];
    private int _index;

    public KeySequenceWatcher(params Key[] sequence)
    {
        _sequence = sequence;
    }

    /// <summary>
    /// Feeds one key press in. Returns true exactly on the press that completed the
    /// sequence, so the caller can react once rather than on every repeat.
    /// </summary>
    public bool Observe(Key key)
    {
        if (_sequence.Length == 0) return false;

        if (key != _sequence[_index])
        {
            // Restart from the beginning, but allow the key that was just pressed to
            // be the first key of a new attempt. Typing the code twice in a row should
            // work, and so should a stray key in the middle.
            _pressed.Clear();
            _index = 0;

            if (key != _sequence[0]) return false;
            _pressed.Add(key);
            _index = 1;
            return _index >= _sequence.Length;
        }

        _pressed.Add(key);
        _index++;

        if (_index < _sequence.Length) return false;

        _index = 0;
        _pressed.Clear();
        return true;
    }

    /// <summary>Forgets any partial sequence, for example after a window loses focus.</summary>
    public void Reset()
    {
        _pressed.Clear();
        _index = 0;
    }
}
