"""recon: extended OSINT reconnaissance package for sherlock-web.

Modules:
    permutations  - username variant generation
    names         - full-name -> username candidate generation
    email_pivot   - gravatar + holehe email checks
    phone_pivot   - offline phone number intel (phonenumbers)
    enrich        - best-effort public profile metadata extraction
    correlate     - cross-account clustering with confidence scores
    engines       - sherlock + maigret scan wrappers used by the SSE endpoint
    pipeline      - unified investigation pipeline (v3)
    graph         - identity-graph JSON builder (v3)
    monitor       - watchlist monitoring with change alerts (v3)
    dossier       - professional dossier report rendering (v3)
    report        - self-contained HTML report rendering

All heavy/optional dependencies (maigret, holehe, phonenumbers) are imported
lazily inside functions so the app boots and the classic endpoints keep
working even if they are missing.
"""
