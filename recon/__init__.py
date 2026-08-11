"""recon: extended OSINT reconnaissance package for sherlock-web.

Modules:
    permutations  - username variant generation
    email_pivot   - gravatar + holehe email checks
    enrich        - best-effort public profile metadata extraction
    correlate     - cross-account clustering with confidence scores
    engines       - sherlock + maigret scan wrappers used by the SSE endpoint
    report        - self-contained HTML report rendering

All heavy/optional dependencies (maigret, holehe) are imported lazily inside
functions so the app boots and the classic endpoints keep working even if
they are missing.
"""
