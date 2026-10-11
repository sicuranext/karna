# karna.sicuranext.com

The public landing page (`index.html`) and the cross-WAF benchmark page
(`benchmark.html`). Plain HTML and CSS, no build step. The technical docs
live in `../docs/` and are published under `/docs/`.

## Layout

- `assets/site.css`: tokens, fonts, nav, buttons and footer shared by both pages.
- `assets/landing.css`, `assets/benchmark.css`: page sections.
- `assets/karna-mark.svg`, `karna-mark-bold.svg` (small sizes, favicon),
  `karna-mark-white.svg` (on ink): the Karna mark.
- `assets/scene/`: the 3D traffic scene in the landing hero, the same
  `kit.js` / `traffic.js` the Karna Console uses, on the console's sample data.
  `assets/vendor/` holds three.js (MIT, see `three-LICENSE.txt`).
- `assets/console/`: Karna Console screenshots, taken from its sample mode.
- `assets/fonts/`: Manrope and IBM Plex Mono, self-hosted (SIL OFL 1.1, license
  texts next to the files).

## Preview

The hero scene is an ES module, so open the pages through a local server:

```sh
cd site && python3 -m http.server 8765
# http://localhost:8765/
```

## Deploy

S3 static website, bucket `karna.sicuranext.com`. The bucket root is this
folder; `/docs/` comes from `../docs/` and `/skill/` is uploaded by
`scripts/package-skill.sh`, so the root sync must leave both alone:

```sh
aws s3 sync docs/ s3://karna.sicuranext.com/docs/ --delete
aws s3 sync site/ s3://karna.sicuranext.com/ --delete --exclude "docs/*" --exclude "skill/*" --exclude "README.md"
```
