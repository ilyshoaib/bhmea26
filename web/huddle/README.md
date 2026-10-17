# huddle — web

**Black Hat MEA 2026 CTF · WEB**

"Huddle" is a small team video-chat app. The flag sits in `/flag.txt` on the
server. Getting it needs **two** bugs chained together.

## Bug 1 — forge an "owner" invite with a hash length-extension

When you ask for an invite, the server gives you a `token` and a signature:

```
sig = SHA256( secret + token )
```

The `secret` is unknown to us. Normally that would stop us from faking a token.
But this signature style is vulnerable to a **length-extension attack**:

- Knowing `SHA256(secret + token)` and the length of `secret`, we can compute a
  **valid** signature for `secret + token + padding + "&role=owner"` **without
  ever knowing the secret**.
- We send that extended token + new signature to `/api/join`. The server checks
  the signature, sees `role=owner`, and makes us the **workspace owner**.

We don't know the secret's length, so the script just tries lengths 16–39 until
one is accepted.

## Bug 2 — read the flag one byte at a time through video thumbnails

As owner we can turn on **video messages**, then upload a video and ask the
server for a **thumbnail** (a tiny preview image).

The trick is in the MP4 we upload. An MP4 has a table (`stco`) that says *where in
the file each video frame starts*. We tamper with that table so the frame offset
points **into `/flag.txt`** instead of into our own video data. The server then
renders a thumbnail from bytes of the flag file.

The thumbnail is a 1-pixel image whose **colour encodes one byte** of the flag
(the video uses an 8-bit palette, so each byte maps to a known colour). We:

1. Upload an MP4 pointing at flag offset `0`, get the thumbnail, read the pixel
   colour, and look it up to recover byte 0.
2. Repeat for offset `1`, `2`, `3`, … rebuilding the flag character by character
   until the server says end-of-file.

`pal8_lookup.json` is the colour → byte table, and `flag_alis.mp4` is the base
video we patch for each offset.

## Run it

```bash
python3 poc.py http://TARGET-HOST/
# optional: skip the secret-length guessing if you know it
python3 poc.py http://TARGET-HOST/ --secret-len 32
```

The script registers a user, forges owner access, enables video messages, then
leaks `/flag.txt` byte by byte and prints the flag.

## Files

- `poc.py` — full exploit
- `flag_alis.mp4` — base video that gets patched per offset
- `pal8_lookup.json` — palette colour → byte lookup table

## Takeaways

- `SHA256(secret + data)` as a signature is unsafe — it can be length-extended.
  Use **HMAC** instead.
- Letting a user control a file offset (here, via the MP4 frame table) turns a
  thumbnail generator into a **file-read oracle**.
