# Dashboard screenshots

Capture the current dashboard from the running SelfSentry installation. Record the
source commit, page, browser, viewport, theme and capture time with each image.
A screenshot documents the displayed state; it does not independently establish
detection accuracy, containment or production readiness.

## Capture procedure

1. Start the managed application and check monitor health.
2. Open the dashboard and configure the operator token privately under
   Monitor → Session credentials. Keep the credentials section closed in images.
3. Capture Overview, an actual incident's evidence drawer, rule review or Monitor
   as needed. Use the existing record IDs from this installation.
4. Check both themes, headings, readable text, complete drawer contents and visible
   error/unavailable states. Presentation mode can enlarge the live Overview.
5. Inspect every image for credentials, personal information and unintended host
   details before sharing. Do not execute mutations just to populate a screenshot.

There is no bundled offline fixture workspace or automatic gallery capture tool.
If the API is unavailable, restore the connection or capture the explicit unavailable
state. Missing records are not replaced with invented incidents or model results.

## Retained historical images

The following files retain their original VM provenance and may show an earlier
interface. They are not new captures of the current release:

- [Alerts](screenshots/alerts-live.png)
- [Monitor](screenshots/monitor-live.png)
- [Models](screenshots/monitor-models-live.png)
- [Rule review](screenshots/rule-review-live.png)

The retired fixture workspace, its capture script and its generated gallery files
remain recoverable from Git history at source commit `e530d7c`. Earlier reports
that describe those captures remain historical records, not current instructions.
