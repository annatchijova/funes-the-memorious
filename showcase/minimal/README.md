# Minimal evidence UI

This is the small TypeScript UI for reading the real-first evidence cases without
touching the existing showcase. It is intentionally a static snapshot: it does
not read bundles, run commands, or claim live QNX status. The collector and
independent verifier remain authoritative.

## Build and serve

```sh
npm install
npm run build
npm run serve
```

Open <http://localhost:4174/> after starting the server.

The selected cases and their claim boundaries are aligned with
[`docs/TEST-CASES.md`](../../docs/TEST-CASES.md). QNX remains explicitly
`BLOCKED` until a real SDP environment produces evidence.
