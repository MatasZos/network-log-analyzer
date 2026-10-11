# NetScope Log Analyzer

Rule-based network log analyzer built as a portfolio project for software engineering, networking and cybersecurity applications.

## Features

- Paste or upload `.log`, `.txt` or `.csv` files.
- Load included sample datasets for mixed suspicious traffic, clean traffic and SSH brute-force attempts.
- Parses common source IP, destination IP, port, protocol and action patterns.
- Flags repeated failed authentication, denied traffic, scan-like behaviour, high-volume sources and unusual management/database ports.
- Shows summary metrics, top source IPs, priority findings and parsed events.
- Exports a plain text report.

## Technologies used

- HTML5
- CSS3
- Vanilla JavaScript
- Browser File API
- Rule-based detection logic
- Static deployment with Vercel

No backend or external dependencies are required. The analyzer runs fully in the browser.

## Detection rules

- Repeated failed authentication from one source IP.
- Scan-like behaviour across multiple destination ports.
- Repeated denied or blocked firewall events.
- High event volume from one source.
- Traffic involving unusual management or database ports.

## Local preview

Open `dist/index.html` in a browser.

## Vercel deployment

Use the same static settings as the portfolio:

- Framework preset: Other
- Build command: leave empty
- Output directory: `dist`

## Next improvements

- Add CSV export for parsed events.
- Add filters for severity, source IP and action.
- Add optional AI-generated summary after the rule-based report is complete.
- Add screenshots to the portfolio once deployed.
