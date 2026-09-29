# Soda

Soda is the Wine runner maintained for Bottles. It tracks Wine and Valve's experimental work, then adds Bottles-specific fixes for Windows applications and games on Linux. Its scope includes desktop software, game launchers, graphics, input, media, Wayland, X11, and Windows API compatibility.

#### Attribution: Wine4Office

The only substantial overlap between the initial Soda Office import and Wine4Office by Elkana Bardugo, an AI-assisted project, was in these two patches:

- `onlineid-web-account-manager.mypatch`: Microsoft 365 sign-in and its OAuth helper. This implementation has since been replaced by the independently written Soda Identity Bridge.
- `windows-web-http-json.mypatch`: less than half of the patch was shared.

Five other patches contained small matching fragments of fewer than 200 lines each. RetailInfo has also been replaced by Soda's declarative WinRT factory. The shared code entered the initial import without attribution, and the remaining overlap stays identified while it is reviewed or replaced.

This acknowledgment remains as a record of those specific contributions to the earlier Soda Office work.
