# Clickjacking Demo — Hidden Flag

A minimal two-page demo of a clickjacking (UI redressing) attack.

- `victim.html` — a fake "SecureBank" page with a **Confirm Action** button.
  Clicking it reveals a hidden flag. This page sets no `X-Frame-Options` /
  `Content-Security-Policy: frame-ancestors` protection, so it can be
  embedded in an `<iframe>` by anyone.
- `attacker.html` — a decoy "Claim Prize" page. It iframes `victim.html`
  with `opacity` near 0 and positions it so the real **Confirm Action**
  button sits exactly under the visible decoy button. The decoy button has
  `pointer-events: none`, so a visitor's click passes through to the
  invisible real button underneath — clicking it without realizing it.

## Run it

```bash
cd clickjacking-demo
python3 -m http.server 8000
```

Open `http://localhost:8000/attacker.html` in a browser and click
**Claim Prize**. The flag appears — but on `victim.html`, not
`attacker.html` — proving the click landed on the hidden iframe.

If the decoy/iframe alignment looks off (browser zoom, font
rendering, etc.), tweak the `top`/`left` values on the `iframe` rule in
`attacker.html`.

## Why it works

`victim.html` never opts out of being framed. A real site prevents this by
sending, on every response:

```
X-Frame-Options: DENY
Content-Security-Policy: frame-ancestors 'none'
```

Add either header (a Python `http.server` won't add them automatically —
you'd need to serve `victim.html` behind something that does, e.g.
Flask/nginx) and reload `attacker.html`: the browser refuses to render the
iframe, the decoy click no longer reaches the hidden button, and the
flag can no longer be captured this way.
