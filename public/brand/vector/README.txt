DOORS — VECTOR FILES (/vector)
==============================

SVG, ink and bone, in the same four configurations as the PNGs:
  lockup-horizontal-*   primary
  lockup-vertical-*     stacked
  wordmark-rule-*       wordmark + rule + subline
  wordmark-only-*       wordmark alone
  icon-ink / icon-bone  square tile
  icon-slab-*-transparent   door slab alone, knob knocked out (true path)

Geometry (icon, tile-relative)
  Tile          1.0 × 1.0
  Door slab     0.40625 wide × 0.625 tall, centered
  Knob          0.0625 square, inset 0.0625 from slab's right edge,
                0.28125 down from the tile top
  Below 24px    omit the knob
All icon art is pure geometry — scales to any size, no font needed.

IMPORTANT — the lettering
  The wordmark and sublines are live <text> in these SVGs:
    Name:    Archivo Medium (500), uppercase, letter-spacing 0.3em
    Subline: IBM Plex Mono Regular, uppercase, letter-spacing 0.22em
  They render correctly anywhere the fonts are installed (both free from
  Google Fonts). Before sending to a printer, sign fabricator, or embroiderer,
  open the file and convert type to outlines (Illustrator: Type > Create
  Outlines; Figma: Outline stroke/Flatten) and save as EPS/PDF/AI as required.
  That one step is what makes these production-safe; the geometry above is
  already final.

Rule weight is 1.5 units against a 24-unit cap height — scale proportionally,
never thicken it independently.
