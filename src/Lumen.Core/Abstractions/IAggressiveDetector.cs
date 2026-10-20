namespace Lumen.Core.Abstractions;

/// <summary>
/// Marks a detector as part of the AGGRESSIVE tier.
///
/// The aggressive rules are the ones that are worth running when the user has asked
/// for maximum sensitivity: they catch real techniques, but they are noisier than the
/// standard rules, so they stay out of the way until somebody asks for them.
///
/// A detector in this tier must still be documented in
/// <c>DetectionCatalog.Rules</c> and must still have a unit test. The tier changes
/// WHEN a rule runs, never WHETHER it is honest.
/// </summary>
public interface IAggressiveDetector
{
}
