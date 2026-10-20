using Lumen.Core.Models;

namespace Lumen.Core.Detection;

/// <summary>
/// A rule that fires when every group of tokens is present. A group is satisfied when at
/// least one of its alternatives appears in the text.
/// </summary>
/// <param name="Id">Stable rule identifier.</param>
/// <param name="Title">Short title shown in the findings list.</param>
/// <param name="Groups">The groups of alternatives. All groups must be satisfied.</param>
/// <param name="Confidence">How much the rule should be trusted.</param>
/// <param name="Detail">Plain-language explanation of what was observed.</param>
/// <param name="Category">The kind of signal the rule produces.</param>
/// <param name="Extensions">Optional list of file extensions the rule applies to.</param>
public sealed record TokenRule(
    string Id,
    string Title,
    IReadOnlyList<IReadOnlyList<string>> Groups,
    Confidence Confidence,
    string Detail,
    FindingCategory Category = FindingCategory.Heuristic,
    IReadOnlyList<string>? Extensions = null)
{
    /// <summary>
    /// Tests the rule against already lower-cased text.
    /// </summary>
    public bool Matches(string lowerText)
    {
        foreach (var group in Groups)
        {
            var satisfied = false;
            foreach (var token in group)
            {
                if (token.Length == 0) continue;
                if (!lowerText.Contains(token, StringComparison.Ordinal)) continue;
                satisfied = true;
                break;
            }

            if (!satisfied) return false;
        }

        return Groups.Count > 0;
    }
}
