# Funes Showcase

The static product frontend lives here. It has no runtime dependency, no
backend, and no access to evidence bundles; the C collector and verifier remain
the authoritative system.

Open `index.html` directly in a browser, or serve this directory locally:

```bash
python3 -m http.server 4173 --directory showcase
```

## Performance budget

- No JavaScript framework or third-party script.
- One above-the-fold visual: `assets/images/evidence-capsule-hero.webp` (88 KB).
- No web fonts; the system font stack prevents font-loading layout shifts.

## Truth boundary

The generated hero is a concept visual. It must never be presented as a
capture of Funes, a QNX execution, or test evidence. The interactive mutation
card is a visual explanation of the verifier's fail-closed behavior.
