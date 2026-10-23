# karna.sicuranext.com

The public landing page (`index.html`) and the cross-WAF benchmark page
(`benchmark.html`). Plain HTML and CSS, no build step. The technical docs
live in `../docs/` and are published under `/docs/`.

## Layout

- `assets/site.css`: tokens, fonts, nav, buttons and footer shared by both pages.
- `assets/landing.css`, `assets/benchmark.css`: page sections.
- `assets/k3d.css`: the 3D scene chrome shared by both pages.
- `assets/karna-mark.svg`, `karna-mark-bold.svg` (small sizes, favicon),
  `karna-mark-white.svg` (on ink): the Karna mark.
- `assets/scene/`: the 3D scenes. `kit.js` / `traffic.js` are the Karna
  Console's (the landing hero runs the traffic scene on the console's sample
  data); `bars.js` draws the benchmark charts, mounted by `bench.js` only
  while each chart is near the viewport.
  `assets/vendor/` holds three.js (MIT, see `three-LICENSE.txt`).
- `assets/console/`: Karna Console screenshots, taken from its sample mode.
- `assets/fonts/`: Manrope and IBM Plex Mono, self-hosted (SIL OFL 1.1, license
  texts next to the files).

## Preview

The scenes are ES modules, so open the pages through a local server. To get
the site and the docs on one origin, as on S3:

```sh
mkdir -p /tmp/karna-preview && cd /tmp/karna-preview
ln -sf ~/Git/karna/site/index.html ~/Git/karna/site/benchmark.html ~/Git/karna/site/assets .
ln -sf ~/Git/karna/docs docs && ln -sf ~/Git/karna/docs/skill skill
python3 -m http.server 8765    # http://localhost:8765/
```

## Deploy

S3 static website, bucket `karna.sicuranext.com`. The bucket root is this
folder; `/docs/` comes from `../docs/` and `/skill/` is uploaded by
`scripts/package-skill.sh`, so the root sync must leave both alone:

```sh
aws s3 sync docs/ s3://karna.sicuranext.com/docs/ --delete
aws s3 sync site/ s3://karna.sicuranext.com/ --delete --exclude "docs/*" --exclude "skill/*" --exclude "demo/*" --exclude "README.md"
```

`/demo/` is the Karna Console's live demo: the console built in demo mode (sample
data, changes kept in the browser tab, a scripted assistant). Rebuild and
publish it whenever the console changes:

```sh
(cd dashboard/web && npm ci && npm run build:demo)
aws s3 sync dashboard/web/dist-demo/ s3://karna.sicuranext.com/demo/ --delete
```
