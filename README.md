# Attribution: Wine4Office

Part of Soda's Office support comes from Wine4Office by Elkana Bardugo, an AI-assisted project. It was included in our initial Office import without attribution, and we're correcting that here.

The shared code is limited to:

- `onlineid-web-account-manager`: Microsoft 365 sign-in, including the OAuth helper. This is largely Wine4Office code.
- `windows-web-http-json`: under half of the patch is shared.
- Small fragments (under 200 lines each) in five other patches.

The remaining 47 of 54 Office patches have no overlap with Wine4Office. That includes rendering, DirectComposition, Wayland integration, Click-to-Run installation and WinRT runtime support. We're renaming the Wine4Office-specific identifiers, and we plan to rework the shared code.
