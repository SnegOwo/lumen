# The cat

Lumen shows a **photograph** of a cat when it raises a detection alert.

## How to use your own picture

1. Save the picture as **`assets/cat.jpg`** (or `assets/cat.png`) in this folder.
2. Rebuild. The picture is embedded in `Lumen.exe` automatically, so it travels inside
   the executable and the published ZIP needs no extra file.

The build does not depend on the picture: if it is missing, the interface falls back to a
simple drawn cat, and everything still works.

## What works best

- A square or portrait image works best — the alert shows the cat at 170 x 170.
- A close-up of the face reads better at that size than a full body.
- Anything PNG or JPEG with a reasonable file size (under ~1 MB) is fine.

## Why a picture and not a drawing

The first version of the cat was drawn with WPF vector shapes. It was rebuilt on every
frame of its little animation, which cost about 11% of a core for nothing, and the
storyboard that drove it eventually crashed the application on every detection.

A photograph is a single bitmap that is loaded once and never redrawn. The only animation
left is a gentle bob, and it moves a transform, so the picture itself is never redrawn
and nothing is allocated per frame.
