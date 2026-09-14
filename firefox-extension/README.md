# NekoRoute Firefox Bridge

This optional Firefox extension lets NekoRoute hand a selected **public proxy** to a real local Firefox tab.

Why this exists: an embedded server-side Firefox would download files onto the server first. With the bridge, Firefox runs on the user's own computer, normal websites/JavaScript work, and downloads are saved by the user's local Firefox. The NekoRoute VPS only creates a short-lived one-time route ticket; it is not in the browsing/download data path after the tab opens.

## Development install

1. Open `about:debugging#/runtime/this-firefox`.
2. Choose **Load Temporary Add-on**.
3. Select `manifest.json` from this folder.
4. Open NekoRoute `/browser`.

For normal public distribution on stable Firefox, package and sign the extension through Mozilla Add-ons (AMO). An unsigned archive is intended for development/testing, not one-click permanent installation.

## Self-hosted NekoRoute

Open the extension settings and add your NekoRoute origin, for example:

`https://proxyweb.example.com`

The default trusted origin is `https://proxyweb.nekosunevr.co.uk`.
