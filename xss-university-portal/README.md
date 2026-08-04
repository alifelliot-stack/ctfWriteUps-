# Stored XSS — University Exam Portal

A single-page demo of a stored (persistent) Cross-Site Scripting attack.
"Riverside State University" has a one-page student portal used by 10
students. Each student can only see their own exam results in the UI — but
the class discussion board renders posted messages as raw HTML with no
sanitization, so any logged-in student can inject a script that runs in
another student's browser session and exfiltrate whatever that session can
see.

## The challenge

- You are **Eve**, an ordinary student. Your own exam results are nothing
  special.
- **Alice** has a confidential remark on her exam record — a "grade appeal
  override code" — that is only ever rendered on Alice's own screen when
  she is logged in.
- There is no way to view another student's results directly: the exam
  panel only ever shows `currentUser`'s own data, and there's no
  IDOR-able endpoint or parameter to tamper with.
- **Goal:** get Alice's confidential remark (the flag) without ever logging
  in as Alice yourself.

The discussion board is the only place user-controlled content is rendered
without escaping — that's the vector.

## Run it

```bash
cd xss-university-portal
python3 -m http.server 8000
```

Open `http://localhost:8000/` in **two separate tabs** (or two windows) of
the same browser — they'll share `localStorage` (the "database") but each
tab keeps its own login (`sessionStorage`), simulating two different
students using the portal at the same time.

## Walkthrough

1. **Tab 1 — log in as `eve`.** In the Discussion Board, post a message
   containing a payload that reads the page's exam remarks and exfiltrates
   them. Since `<script>` tags inserted via `innerHTML` don't execute, use
   an event-handler trick instead, e.g.:

   ```html
   <img src=x onerror="
     var r = document.getElementById('examRemarks');
     var who = document.getElementById('whoami').textContent;
     if (r) {
       localStorage.setItem('leak_' + Date.now(), who + ' -> ' + r.textContent);
     }
   ">
   ```

   Click **Post message**. Nothing looks wrong yet — Eve has no remarks, so
   `examRemarks` doesn't exist in Eve's own view and nothing fires.

2. **Tab 2 — log in as `alice`.** As soon as Alice's dashboard renders the
   discussion board, the stored `<img onerror>` payload executes *in
   Alice's session*. At that moment `examRemarks` exists in the DOM and
   contains her confidential remark, so the script reads it and writes it
   to `localStorage` under a `leak_...` key.

3. **Back in Tab 1**, the `storage` event fires (localStorage changed in
   another tab), the page re-renders, and the **📡 External Network
   Monitor** panel — standing in for a server the attacker controls —
   now shows Alice's leaked remark, including the flag.

You never logged in as Alice, and there was no direct way to request her
data. The victim's own browser did the work of reading it and handing it
to the attacker.

## Why it works

- **No output encoding**: the discussion board does
  `messageBodyElement.innerHTML = message.text` on attacker-controlled
  input instead of `textContent` (see the comment in `index.html` marking
  the exact line).
- **Stored, not reflected**: the payload is saved to the shared "database"
  (`localStorage.uni_messages`) once and then executes for *every* user who
  views the board afterward — including the victim, without them doing
  anything except loading the page while logged in.
- **Same-origin trust**: because the payload runs as genuine JavaScript in
  Alice's authenticated session, it has exactly the same DOM access Alice
  has — which is the whole point of a same-origin script. There's no
  browser boundary left to cross once the injection succeeds.
- In a real deployment the exfiltration line would be a `fetch()`/`XHR`
  call to an attacker-controlled domain; this demo swaps that for
  `localStorage` + the `storage` event purely so the whole thing runs from
  static files with no network or backend required.

## The fix

- **Escape/encode on output.** Render user-generated message text with
  `textContent` (or an HTML-escaping helper) instead of `innerHTML`. If
  rich formatting is genuinely needed, sanitize with an allowlist-based
  library (e.g. DOMPurify) *server-side and client-side*, never trust
  client input as-is.
- **Content-Security-Policy.** Serve
  `Content-Security-Policy: script-src 'self'; object-src 'none'` (and
  avoid inline event handlers/`unsafe-inline`) so even a successful
  injection of markup can't execute attacker JavaScript.
- **Don't co-locate secrets with unsanitized render paths.** Confidential
  fields like the grade-appeal code shouldn't be dumped into the same DOM
  that renders untrusted third-party content — fetch them separately, on
  demand, from an endpoint that itself enforces authorization.
- **HttpOnly / scoped storage.** In a real app, session tokens should be
  `HttpOnly` cookies (unreachable from JS) rather than something readable
  by any script that manages to execute — XSS should not automatically
  mean full session takeover.

Apply the `textContent` fix to the `renderMessages()` function in
`index.html`, reload, and repeat the walkthrough — the payload now renders
as inert text and the discussion board is no longer exploitable.
