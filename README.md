# Soda

Soda is the Wine runner maintained for Bottles. It tracks Wine and Valve's experimental work, then adds Bottles-specific fixes for Windows applications and games on Linux. Its scope includes desktop software, game launchers, graphics, input, media, Wayland, X11, and Windows API compatibility.

#### Soda Identity Bridge

Soda Identity Bridge connects Windows authentication APIs to a Linux broker, with system-browser sign-in using Authorization Code with PKCE and tokens stored in the desktop credential store.
Bottles provides a native sign-in dialog; outside Bottles, Soda provides its own device-code fallback. Soda's declarative WinRT factory handles class activation, including RetailInfo.

#### Special thanks

Thanks to Elkana Bardugo for Wine4Office, an AI-assisted project. We used its authentication and HTTP/JSON code in `onlineid-web-account-manager.mypatch` and `windows-web-http-json.mypatch` during development. Authentication now uses Soda Identity Bridge; some HTTP/JSON code and small fragments elsewhere remain Wine4Office-derived.
