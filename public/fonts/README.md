# Self-hosted fonts

Source Serif 4, vendored so the browser loads the app's typeface from this
origin instead of a third-party font CDN. Collapsing the last cross-origin
request out of the browsing path is the point: see the CSP notes in `server.js`.

## Provenance

- **Family / axis string:** `Source Serif 4:ital,opsz,wght@0,8..60,400..700;1,8..60,400`
  (the exact axes both pages requested before this change: the optical-size axis
  8..60, the full 400..700 weight range for upright, and weight 400 for italic).
- **Version:** the `v14` webfont build of Source Serif 4.
- **Retrieved:** 2026-07-22, via the CSS webfont API (fetched with a modern
  Chrome User-Agent so the API served woff2). The exact retrieval URL is recorded
  in the commit that vendored these files; it is kept out of the working tree so
  the app carries no textual reference to its former font host.
- **Upstream:** Source Serif 4 is Adobe's typeface; the master sources and the
  license live at https://github.com/adobe-fonts/source-serif.
- **Subsets vendored:** `latin` and `latin-ext` only, each in upright (roman)
  and italic. The other subsets the API offers (cyrillic, cyrillic-ext, greek,
  vietnamese) are not shipped: this app's copy is English, and the
  `unicode-range` declarations in `broadsheet.css` mean a browser only fetches a
  file when the page actually uses a glyph in its range.

## Files

| File | Style | Weight | Subset |
|------|-------|--------|--------|
| `source-serif-4-roman-latin.woff2`      | normal | 400 700 | latin |
| `source-serif-4-roman-latin-ext.woff2`  | normal | 400 700 | latin-ext |
| `source-serif-4-italic-latin.woff2`     | italic | 400     | latin |
| `source-serif-4-italic-latin-ext.woff2` | italic | 400     | latin-ext |

The `@font-face` rules that wire these in (with the matching `unicode-range`
values) live at the top of `public/css/broadsheet.css`.

## License

Source Serif 4 is licensed under the SIL Open Font License, Version 1.1. The
full license text, including Adobe's copyright and Reserved Font Name notice,
is in `OFL.txt` in this directory. Redistribution requires the license to
travel with the font files, so keep `OFL.txt` alongside the woff2 files.
