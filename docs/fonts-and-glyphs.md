# Fonts and glyphs in the signature stamp

The visible signature stamp is drawn with a bundled copy of Noto Sans Regular (SIL OFL 1.1), so the stamp looks and measures the same on every machine. The system font configuration (fontconfig) is not consulted.

Noto Sans covers Latin, Greek and Cyrillic. It has no Devanagari or CJK glyphs. If the certificate's common name contains such a character, the stamp shows `?` in its place and signing prints a warning. The signature and the certificate keep the real name; only the drawn text changes.

If the bundled font file is missing or unreadable, signing falls back to pyHanko's built-in standard font instead of failing (set `DSC_DEBUG` to see a note on stderr).
