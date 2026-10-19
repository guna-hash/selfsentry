# Dashboard screenshot capture

The redesign gallery uses the synthetic `/sample/` workspace in both themes.
Its banner stays visible. These images document the interface, not live security
activity or evaluation results. Existing `*-live.png` files remain historical
VM evidence of the earlier interface and are not relabelled as redesign captures.

## Capture plan

| View | Sample route | Files (light and dark) |
|---|---|---|
| Overview | `/sample/overview` | `redesign-overview-{light,dark}.png` |
| Incident evidence | `/sample/alerts?incident=9001` | `redesign-incident-{light,dark}.png` |
| Rule review | `/sample/rules?rule=9102` | `redesign-rule-review-{light,dark}.png` |
| Presentation | `/sample/overview?present=1` | `redesign-presentation-{light,dark}.png` |

The eight PNGs were captured with Chrome for Testing 151.0.7922.34 against the
production Vite preview. Desktop viewport: 1600×1200, device scale 1, reduced motion.
Locale: en-IN; timezone: Asia/Kolkata; sample clock: 2026-10-19T12:00:00.000Z.
Full-page Overview/presentation images extend below the viewport; modal images show
the visible drawer portion and retain the background Sample data notice.
All eight were inspected for theme consistency, headings, chart/table rendering,
sample provenance and clipping. Captures do not assert real incident/model accuracy.

The script waits for loaded data, theme, fonts and charts. It checks native modal
Tab/Shift+Tab/Escape and 390px layout/navigation in both themes. Cross-origin/backend
requests, non-GET requests, authorization headers and page JavaScript errors fail
capture. No operator token is supplied. The observed checks are recorded in
[screenshot report](screenshots/redesign-capture-report.json).

Images are staged temporarily. Only after the complete capture/check run succeeds
are eight PNGs and the report copied into `docs/screenshots/` and the labelled README
gallery inserted or replaced. Re-running updates one gallery; historical images
remain untouched. Review images before committing. These checks are bounded browser
smoke tests, not exhaustive accessibility certification or live response acceptance.
Existing theme-token tests cover declared contrast pairs, not every rendered state.

## Reproduce on your VM

Playwright is an optional capture tool; it is not added to the project or its
lockfile. Install it separately if you want to regenerate the included images:

```bash
npm install --prefix /tmp/selfsentry-capture-tools --no-package-lock playwright
/tmp/selfsentry-capture-tools/node_modules/.bin/playwright install chromium
```

Build and serve in one terminal:

```bash
cd ~/selfsentry/frontend-dashboard
npm ci && npm run build
./node_modules/.bin/vite preview --host 127.0.0.1 --port 5173 --strictPort
```

In another terminal:

```bash
cd ~/selfsentry/frontend-dashboard
PLAYWRIGHT_MODULE_PATH=/tmp/selfsentry-capture-tools/node_modules/playwright \
  node scripts/capture-dashboard.mjs
```

The backend is not needed. Capture defaults to `http://127.0.0.1:5173` and accepts only
a local HTTP origin. Set `SELFSENTRY_CAPTURE_ORIGIN` for a different frontend port,
for example `http://127.0.0.1:5198`. If system libraries are missing, follow the
browser installation error for your OS. `SELFSENTRY_BROWSER_EXECUTABLE` can identify
a compatible Chromium binary already installed locally. A browser is required; do
not replace captures with generated artwork, DOM mocks or edited screenshots.

## Review and share

- Check both themes for readable text, complete headings and visible sample labels.
- Inspect drawers for evidence, advisory AI and disabled sample write controls.
- Check presentation for larger text, incident focus and learning-loop counts.
- Check the report's browser version, sample URLs and bounded checks.
- Keep raw study artifacts, personal information and credentials out of images.

To share regenerated images for review:

```bash
cd ~/selfsentry
tar -czf ~/Downloads/selfsentry-dashboard-screenshots.tar.gz \
  docs/screenshots/redesign-*.png \
  docs/screenshots/redesign-capture-report.json
```

This archive contains UI examples, not new academic results. No rule approval,
container action, backend mutation or experimental trial is part of capture.
