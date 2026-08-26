# God's Eye View — geospatial workspace

sherlock-web can embed **[God's Eye View](https://github.com/bilawalsidhu/gods-eye-view)**
(by Bilawal Sidhu, MIT) as a `[GEO] God's Eye` workspace tab — a photorealistic
3D globe of live open-source spatial intelligence (flights, vessels, satellites,
fires, quakes, CCTV, radio, launches, …).

It is a **separate service** with its own stack (Vite/Node + Cesium) and its own
API keys. sherlock-web does **not** bundle, proxy, or hold its keys — it only
detects whether the service is up and embeds it in an `<iframe>`. Keys stay on
your machine.

## Run it

```bash
./scripts/godseye.sh
```

That clones it once into `./godseye/` (gitignored), installs its dependencies
(skipping the Puppeteer browser download), creates `godseye/.env` from the
template, and starts its dev server on `http://localhost:4173`. Then open the
**God's Eye** tab in sherlock-web and click **Recheck** — it embeds the globe.

## Keys

Only one key is **required**, and only for the 3D globe itself:

- `GOOGLE_MAPS_API_KEY` — Google Cloud → enable the **Map Tiles API**. It is
  client-exposed by design, so scope it (HTTP-referrer + API restriction).

Everything else is **optional** — the free/anonymous layers (flights via
anonymous OpenSky, satellites, fires, earthquakes, radio, rocket launches, …)
work with no keys. Opt-in extras: `OPENAI_API_KEY` (voice control),
`CESIUM_ION_TOKEN` (extra imagery), OpenSky OAuth (higher aircraft rate limits).
The launcher defaults `OPENSKY_AUTH_MODE=anon` so aircraft work with no account.

Put keys in `godseye/.env` (see `godseye/.env.example`). Set provider-side
budget alerts — the Google/OpenAI layers are metered.

## Configuration

- `GODSEYE_URL` (sherlock-web env) — where the tab looks for the service.
  Defaults to `http://localhost:4173`. Set it if you host God's Eye elsewhere.
- `GODSEYE_PORT` (launcher env) — the port `scripts/godseye.sh` binds. Default `4173`.

## Notes

- This is a **different domain** from sherlock-web's identity OSINT — it tracks
  real-world objects, not a subject's accounts. It's a companion lens, not part
  of the identity pipeline.
- The app is vendored on demand (not committed); `godseye/` is gitignored.
- Not running / no key → the tab shows setup instructions instead of a blank
  globe.
