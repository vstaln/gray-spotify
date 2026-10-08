<p align="center">
  <img src="assets/gray-logo.svg" alt="gray" width="96">
  <img src="assets/spotify.svg" alt="spotify" width="96">
</p>
<h1 align="center">gray-spotify</h1>
<p align="center">Spotify playback, queue, and search via the Web API + PKCE OAuth.</p>
<p align="center">
  <a href="https://github.com/vstaln/gray-spotify/blob/main/LICENSE"><img alt="MIT License" src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
  <img alt="gray plugin" src="https://img.shields.io/badge/gray-plugin-7aa2f7.svg">
  <img alt="rust" src="https://img.shields.io/badge/built%20with-rust-orange.svg">
</p>

Control Spotify from the agent: play, pause, next/prev, queue, search, what's-playing, and volume — through the Web API with PKCE OAuth.

## What it does

- `spotify` tool: `{action: "play"|"pause"|"next"|"prev"|"queue"|"search"|"now"|"volume", query?, uri?, percent?}`
  - `play` with a `uri` plays it; with a `query` it resolves the top search hit; bare resumes.
  - `queue` accepts `uri` or `query`. `search` returns the top 5 tracks (`name — artists [album] (uri)`).
  - `now` shows the current track; `volume` takes `percent` 0–100.
- `/spotify auth` runs the OAuth PKCE flow: prints the authorize URL (and
  surfaces it via `host/say` when granted), reads the pasted `code` / full
  redirect URL via `host/ask`, exchanges it, and stores tokens in
  `~/.gray/spotify/token.json`. Fallback: `/spotify code <code-or-url>`.
- Access tokens are refreshed once on 401 with the stored refresh token.
- `/spotify status`, `/spotify logout`.

## Setup

Create an app at https://developer.spotify.com/dashboard, add the redirect URI
`http://127.0.0.1:43827/spotify/callback` (or set `SPOTIFY_REDIRECT_URI`), then:

```sh
export SPOTIFY_CLIENT_ID=<your app client id>
```

## Wire methods

`plugin/manifest`, `tool/call`, `command/run`, `plugin/shutdown` — protocol 1.1.
Capabilities `host.ask` + `host.say` are used for the auth flow; the tool works
without them once tokens exist.

```sh
gray plugin capabilities spotify --all
```

## Install

```sh
gray plugin install spotify
```

## Develop

```sh
cargo test
gray account check      # entry point + manifest handshake
gray account publish    # check → build → release → publish to the gray registry
```

---
Part of the [gray](https://github.com/vstaln/gray) plugin ecosystem —
the open-source AI agent harness. <https://gray.alignment.id>
