# Lumen UI review — theme layer

Scope: `src/Lumen.App/Themes/**`, `src/Lumen.App/Controls/**`, `src/Lumen.App/Dialogs/**`,
`src/Lumen.App/Infrastructure/Commands.cs`, `src/Lumen.App/Infrastructure/MotionExtension.cs`.

This is a visual and accessibility refactor of the design system. It does **not** change what the
app does; it changes how the app looks, how it responds to input, and how it is announced by a
screen reader.

---

## 1. Dictionary layout

```
src/Lumen.App/Themes/
  Tokens.xaml            spacing, radii, type ramp, icon sizes, heights, motion
  Icons.xaml             Segoe Fluent Icons / MDL2 glyphs as named strings
  Colors.Light.xaml      colour dictionary (light)
  Colors.Dark.xaml       colour dictionary (dark)
  Colors.HighContrast.xaml  colour dictionary (high contrast)
  Controls.xaml          aggregator: the single file App.xaml merges
  Controls/
    Base.xaml            window chrome (AppWindow + implicit Window style)
    Focus.xaml           the shared focus ring (FocusVisual)
    Typography.xaml      PageTitle … StatNumber
    Buttons.xaml         ButtonBase, Primary/Secondary/Danger/Icon/Link/Nav
    Inputs.xaml          ToggleSwitch, SelectionCheckBox, PillRadio, ChoiceCard, RangeSlider
    Surfaces.xaml        Card, InsetCard, Divider
    Chips.xaml           ChipBorder, ChipText, BadgeBorder, BadgeText
    Lists.xaml           CleanListBox, CleanListBoxItem
    Progress.xaml        ScanProgressBar
    Scrollbars.xaml      implicit ScrollBar style
    Tooltips.xaml        implicit ToolTip style
```

`App.xaml` is unchanged: it still merges `Themes/Controls.xaml` and `Themes/DataTemplates.xaml`.

The three colour dictionaries stay separate on purpose: `ThemeService` swaps them at runtime by
inserting the active one at `Application.Current.Resources.MergedDictionaries[0]`.

### One rule that the split forces

`{StaticResource}` is resolved **when the dictionary is loaded**, against that dictionary's own
scope. A token that lives in `Tokens.xaml` is therefore *not* visible to `Buttons.xaml` unless
`Buttons.xaml` merges `Tokens.xaml` itself. Every dictionary under `Controls/` therefore merges
`../Tokens.xaml` (and `Focus.xaml` where it needs the focus ring). This was verified by loading
the dictionaries and applying every style to a real control: an unresolvable `StaticResource`
does not throw, it silently becomes `DependencyProperty.UnsetValue` and only fails later, when
the template is materialised.

---

## 2. Tokens

All tokens live in `Themes/Tokens.xaml`. They are theme independent — colours never appear here.

### Spacing (`Thickness`)

| Key | Value | Meaning |
|---|---|---|
| `Space.Xs` | 4 | hairline gap (tool tip margin) |
| `Space.Sm` | 8 | tight gap inside a component |
| `Space.Md` | 12 | default gap, inset card padding |
| `Space.Lg` | 16 | card padding, gap between blocks |
| `Space.Xl` | 24 | dialog content margin |
| `Space.Xxl` | 32 | dialog surface margin |

Asymmetric composites (a `Thickness` scale cannot express them): `Space.Top.Xs`, `Space.Top.Sm`,
`Space.Top.Lg`, `Space.Top.Xl`, `Space.Bottom.Xs`, `Space.Vertical.Md`, `Space.Horizontal.Md`,
`Space.Horizontal.Lg`, `Space.Inset.Xs`, `Space.Inset.Tight`, `Space.Pill`, `Space.ListItem`,
`Space.Nav`.

### Corner radii (`CornerRadius`)

| Key | Value | Meaning |
|---|---|---|
| `Radius.Xs` | 4 | small elements, scroll bar thumb, check box |
| `Radius.Sm` | 6 | tool tip |
| `Radius.Md` | 8 | pill radio |
| `Radius.Lg` | 12 | inset card, choice card, toggle track |
| `Radius.Xl` | 16 | card, dialog |
| `Radius.Control` | 8 | every interactive surface (button, list item) |
| `Radius.Focus` | 11 | focus ring = `Radius.Control` + 3 |
| `Radius.Pill` | 99 | chips and badges |

### Type ramp (`double`)

`Font.Size.Micro` 11 · `Font.Size.Small` 12 · `Font.Size.Body` 14 · `Font.Size.Large` 18 ·
`Font.Size.Display` 24 · `Font.Size.Hero` 32.

The ramp replaces the 21 hard coded font sizes that the views used. The theme picks a step from
the ramp; the views should do the same.

### Icon sizes (`double`)

`Icon.Size.Small` 16 · `Icon.Size.Medium` 20 · `Icon.Size.Large` 24 · `Icon.Size.XLarge` 32 ·
`Icon.Size.Hero` 40.

### Control heights (`double`)

`Control.Height.Small` 28 · `Control.Height.Medium` 32 · `Control.Height.Default` 38 ·
`Control.Height.Large` 44.

### Border widths

`Border.Width.Hairline` 1 and `Border.Width.Thick` 2 (`double`), plus
`Border.Thickness.Hairline` 1 (`Thickness`).

> **Why the double exists twice:** WPF cannot assign a `double` to a `Thickness` property — the
> `Thickness` type converter only understands text. Using the double token in a `BorderThickness`
> setter produces a hard runtime failure (“`DependencyProperty.UnsetValue` is not a valid value
> for the property `BorderThickness`”).

### Focus ring

`Focus.Ring.Thickness` (2, `Thickness`) and `Focus.Ring.Margin` (-3, `Thickness`).

### Motion

`Motion.Fast` 120 ms · `Motion.Normal` 180 ms · `Motion.Slow` 240 ms — as `TimeSpan`.

A `TimeSpan` cannot be assigned to `Timeline.Duration`, so `Infrastructure/MotionExtension.cs`
converts a token into a `Duration`:

```xml
xmlns:infra="clr-namespace:Lumen.App.Infrastructure"
…
Duration="{infra:Motion Motion.Fast}"
```

The extension falls back to 180 ms when the token cannot be found, so a missing token can never
stop a template from loading. The tokens are used by the scroll bar thumb (hover fade,
`Motion.Fast`), the tool tip (fade in, `Motion.Normal`) and the dialog (fade in, `Motion.Slow`).

---

## 3. Icons

`Themes/Icons.xaml` publishes the glyphs the app already draws as named string resources, so the
private-use codepoints stop being magic numbers. Each value is the literal glyph character.

| Key | Glyph | | Key | Glyph |
|---|---|---|---|---|
| `Icon.Home` | E80F | | `Icon.Radar` | E9F9 |
| `Icon.Search` | E721 | | `Icon.Refresh` | E72C |
| `Icon.Scan` | E721 | | `Icon.Info` | E946 |
| `Icon.Trash` | E72E | | `Icon.Warning` | E7BA |
| `Icon.List` | E81C | | `Icon.Error` | EA39 |
| `Icon.Gear` | E713 | | `Icon.Check` | E73E |
| `Icon.Profile` | E77B | | `Icon.Dismiss` | E711 |
| `Icon.FullScan` | E9D9 | | `Icon.Shield` | EA18 |
| `Icon.Folder` | E8B7 | | `Icon.ScriptRule` | E943 |
| `Icon.File` | E7C3 | | `Icon.FilenameRule` | E8A5 |
| `Icon.Moon` | E706 | | `Icon.Chevron` | E76C |
| `Icon.Sun` | E708 | | | |
| `Icon.SystemTheme` | E770 | | | |

Usage: `<TextBlock Text="{StaticResource Icon.Shield}" FontFamily="Segoe Fluent Icons, Segoe MDL2 Assets" />`
— always together with `AutomationProperties.Name=""` on decorative glyphs.

`Icon.Search` and `Icon.Scan` are the same glyph (E721); the app uses it for both "search" and
"quick scan".

The theme itself uses `Icon.Info`, `Icon.Check`, `Icon.Warning`, `Icon.Error`, `Icon.Dismiss`
and `Icon.Trash`. The remaining eighteen are for the views: they still contain the raw
`&#xE…;` entities for exactly these glyphs, and the project-wide dead resource scan will keep
flagging them until the views reference the named resources instead.

---

## 4. Interaction states

Every state below was missing before and is now present:

| Style | Added |
|---|---|
| `NavButton` | `IsEnabled=False` (dimmed, arrow cursor), `IsPressed` |
| `SelectionCheckBox` | `IsEnabled=False`, `IsPressed`, keyboard focus border |
| `PillRadio` | `IsEnabled=False`, `IsPressed` |
| `ChoiceCard` | `IsEnabled=False`, `IsPressed` |
| `CleanListBoxItem` | `IsEnabled=False` |
| `IconButton` | `IsPressed` |
| `LinkButton` | `IsPressed` |
| `DangerButton` | `IsPressed` (new colour `Danger.PrimaryPressed`) |
| `DangerOutlineButton` | `IsPressed` |
| `ScrollBar` thumb | hover (accent, fading in), dragging (accent primary) and disabled states |

`SecondaryButton`, `PrimaryButton` and `ToggleSwitch` already had hover/checked states and keep
them.

The vertical scroll bar also now has a real thumb travel: the old template hard-coded
`IsDirectionReversed="True"`, which is right for a vertical track and wrong for a horizontal one.
The template now reverses the direction only when the orientation is horizontal, so both
orientations behave (verified by measuring the thumb position at the minimum and the maximum).

---

## 5. Elevation

Cards no longer render a shadow.

* The light theme used a `DropShadowEffect` with a 16 px blur. Up to nine of those were alive at
  once on the dashboard, each one a software rendered blur on a scrolling page.
* All three themes now use a flat card: a 1 px border (`App.Border`) plus a background that is a
  shade away from the page (`App.SurfaceCard`).
* `Card.Effect` still exists as a key in every theme (resolving to a null effect) and the `Card`
  style still honours it, so a future theme can opt into real elevation without touching the
  styles.

Dark and High Contrast keep their flat-with-border behaviour, unchanged.

---

## 6. Progress bar

`ScanProgressBar` previously ignored `ProgressBar.Value`: a determinate bar rendered nothing at
all. The template now uses the standard WPF template parts (`PART_Track` / `PART_Indicator`), so
`ProgressBar` measures the indicator against the track and the fill follows `Value`. The sweeping
pulse is only shown when `IsIndeterminate` is true.

---

## 7. Focus

* `FocusVisual` used `CornerRadius="10"` while the button template used `9`, so the ring clipped
  into the rounded corner instead of hugging it. Both now come from the token layer:
  `Radius.Control` (8) for the control, `Radius.Focus` (11) for the ring. The ring is drawn 3 px
  outside the control, so its radius has to grow by the same amount — the two values live next to
  each other in `Tokens.xaml` and can no longer drift apart.
* `InputTextBox` used `FocusVisualStyle="{x:Null}"` and only a 1 px border colour change as its
  focus indicator. **The style was unreferenced anywhere in the app, so it has been removed**
  (see §10). Every surviving focusable control — buttons, switches, radios, choice cards, list
  items — uses the shared 2 px accent focus ring, and the check box additionally brightens its
  border with `Input.BorderFocus` when the keyboard is on it.

---

## 8. High contrast hero

The hero is a dark gradient island in the light and the dark theme, so its buttons are light on
dark. In the high contrast theme the hero uses the system window colour, which makes it a *light*
island — so its button colours have to follow the system colours instead of the mint and teal of
the brand themes.

| Key | Light / Dark | High contrast |
|---|---|---|
| `Hero.ButtonBg` | `#F0FDFA` | `SystemColors.Highlight` |
| `Hero.ButtonFg` | `#082F2C` | `SystemColors.HighlightText` |
| `Hero.ButtonBgHover` | `#CCFBF1` | `SystemColors.Highlight` |
| `Hero.ButtonBgPressed` | `#99F6E4` | `SystemColors.Highlight` |
| `Hero.ButtonBorder` | `#F0FDFA` | `SystemColors.HighlightText` |
| `Hero.GhostBg` | `#14FFFFFF` | transparent |
| `Hero.GhostFg` | `#F8FAFC` | `SystemColors.WindowText` |
| `Hero.GhostBorder` | `#3B6470` | `SystemColors.WindowText` |
| `Hero.Ring` | `#552DD4BF` | `SystemColors.WindowText` |
| `Hero.GlyphFg` | `#7DE6D7` | `SystemColors.WindowText` |

These ten keys exist in all three colour dictionaries, and the three dictionaries still expose an
identical key set (72 keys each) so a theme switch can never half-apply.

---

## 9. New and changed public keys

### New colour keys (all three themes)

`Hero.ButtonBg`, `Hero.ButtonFg`, `Hero.ButtonBgHover`, `Hero.ButtonBgPressed`,
`Hero.ButtonBorder`, `Hero.GhostBg`, `Hero.GhostFg`, `Hero.GhostBorder`, `Hero.Ring`,
`Hero.GlyphFg`, `App.SurfaceCard`, `App.ShadowColor` (a `Color`), `Danger.PrimaryPressed`.

### New style keys

`RangeSlider` — a themed `Slider`. The settings page used to fall back on the stock WPF slider;
it has to apply `Style="{StaticResource RangeSlider}"` to pick the new look up.

### Removed keys

See §10.

---

## 10. Dead resources

Each key was grepped over the whole `src` tree (including the files the other agents added)
before removal. All of them were genuinely unreferenced.

**Styles** (removed): `Body`, `CardFlat`, `GhostButton`, `IconButtonOnDark`, `InputTextBox`,
`LinkText`.

**Brushes** (removed from all three colour dictionaries): `App.BackgroundAlt`, `App.TextOnDark`,
`App.TextOnDarkMuted`, `Dialog.Scrim`.

### Contradictions in the brief, and how they were resolved

* Task 9 asks for `IconButtonOnDark` to be deleted, task 4 asks for a pressed state on it. The
  style was unreferenced, so it was deleted; the pressed state went to the styles that survive.
* Task 9 asks for `InputTextBox` to be deleted, task 7 asks for its focus ring to be fixed. The
  style was unreferenced, so it was deleted and the focus ring work went into the shared
  `FocusVisual` and the new `RangeSlider`.

### Kept on purpose

* `CountToVisibilityConverter` and `InverseBooleanConverter` are registered in `App.xaml` and
  defined in `Infrastructure/Converters.cs`, but **no view uses them** (verified by grep over the
  whole tree). They were left in place: `App.xaml` belongs to another agent, and removing the
  types from `Converters.cs` would break its compilation. Removing them needs one line in
  `App.xaml` plus the two classes.
* `Card.Effect` is kept as the elevation extension point (see §5).
* `Input.BorderFocus` is kept: it belongs to the `Input.*` palette family and is now used by the
  check box focus state.

---

## 11. Behaviour changes that affect the rest of the app

### `ConfirmDialog` — the Enter key

**Before:** `PrimaryButton.IsDefault = !options.IsDanger`. On a destructive dialog no button was
the default, so pressing Enter did nothing at all.

**After:**

| Dialog | Default button (Enter) | Focus |
|---|---|---|
| normal | the primary button | primary |
| danger, cancel shown | **the cancel button** | cancel |
| danger, no cancel button | none (Enter does nothing) | cancel (hidden) |

Enter therefore always means the safe choice. The destructive button is never the default.

Other `ConfirmDialog` changes:

* The accessible name of the window is now the **title only**. It used to be
  `title + ". " + message`, which made a screen reader announce the message twice (once as the
  window name and once from the visible text).
* The message is now inside a `ScrollViewer` with a bounded `MaxHeight` of 240. With
  `SizeToContent="Height"` and `MaxHeight="680"` a long message used to be silently clipped.
* The read-only details box is `IsTabStop="False"`. It was a tab stop even though it cannot be
  edited, so keyboard users landed in an editable-looking control.
* The drop shadow colour is now the themed `App.ShadowColor` instead of a hard coded `#000000`.
* The severity glyph, the banner glyph and the empty state glyph carry
  `AutomationProperties.Name=""` so a screen reader never reads a private-use codepoint.

### `AsyncRelayCommand`

The failure handler used to write to `Debug.WriteLine`, which disappears in Release builds: a
failed async command was an invisible failure.

* The constructor gained an optional third parameter, `Func<Exception, Task>? onError`.
  `new AsyncRelayCommand(func, canExecute)` keeps working unchanged.
* `AsyncRelayCommand.WithErrorHandler(execute, onError, canExecute)` is available for a
  synchronous handler.
* **Without a handler the exception is now rethrown on the UI thread** (with the original stack
  preserved) instead of being swallowed. `App.OnDispatcherUnhandledException` logs it and shows
  the user a message, so the failure becomes visible without taking the process down.
* `OperationCanceledException` is still treated as a normal outcome and is not reported.

### `RelayCommand<T>`

A parameter of the wrong type used to make `CanExecute` return `false` with no explanation, so a
binding mistake looked like a disabled button.

* `CanExecute` now writes the mismatch to `Trace` (compiled into Release builds, unlike
  `Debug.WriteLine`) and returns `false`.
* `Execute` throws an `InvalidCastException` that names both types.

This was the chosen option of the two the brief offered (“throw, or treat as cannot-execute and
log it”): the button degrades safely, and a direct call is loud.

---

## 12. Visual changes worth knowing about

* Type sizes now come from the ramp. The most visible: page titles and the big statistics number
  are 32 instead of 30, section titles 18 instead of 17, card titles 14 instead of 15, labels 14
  instead of 13, secondary body copy 12 instead of 13 and captions 11 instead of 12. Button text
  is 14 instead of 13.
* Cards use 16 px padding instead of 20, inset cards 12 instead of 14, list items 12/10 and choice
  cards 12 instead of 14.
* Interactive surfaces use `Radius.Control` (8) instead of 9/10.
* `IconButton` is 32×32 by default (it was 36×36); the views that need a different size set it
  explicitly, as most of them already did.
* `LinkButton` keeps its 24 px height on purpose: it has to sit on a text baseline, which is
  shorter than the control height scale.
* The light theme lost its card shadow (see §5).
* The banner, the dialog and the empty state now use the named icon resources, so their glyphs
  follow the theme instead of being hard coded.

---

## 13. How this was verified

The theme was not only compiled but **loaded and exercised**: the dictionaries were loaded from a
built assembly, every style was applied to a real control and laid out, the determinate progress
bar was measured at 50 % and at 100 %, the scroll bar thumb was measured at the minimum and the
maximum for both orientations, the three colour dictionaries were compared key by key, and the
high contrast hero colours were compared with `SystemColors`. The `ConfirmDialog` was constructed
and its default-button, accessible-name and scroll-viewer state was inspected, and the command
classes were executed.

Nothing was launched: no window of the application was shown.
