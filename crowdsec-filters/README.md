# linagora-llng-crowdsec-filters

Pattern-based HTTP filters used by LemonLDAP::NG's built-in CrowdSec agent to
detect and report suspicious requests (admin probing, backdoor attempts,
trending CVE URIs, path traversal, WordPress scans, etc.).

Files are installed under `/var/lib/lemonldap-ng/crowdsec-filters/`.

## Requirements

- **LemonLDAP::NG >= 2.23.0** — the `crowdsecFilters` feature is not available
  in earlier versions.
- A reachable CrowdSec LAPI (local or remote) the portal can push alerts to.

## Configuration

In the LemonLDAP::NG Manager, set:

| Parameter          | Value                                      |
|--------------------|--------------------------------------------|
| `crowdsecFilters`  | `/var/lib/lemonldap-ng/crowdsec-filters`   |
| `crowdsecAgent`    | `http://crowdsec:8080` (your LAPI URL)     |
| `crowdsecMachineId`| machine id registered on the LAPI          |
| `crowdsecPassword` | password for that machine id               |

Register the portal on the CrowdSec LAPI beforehand:

```sh
cscli machines add llng --password '<pick-a-password>'
```

Then reload the portal.

See the [LemonLDAP::NG documentation](https://lemonldap-ng.org/documentation/)
for full details on the CrowdSec integration.

## Filter layout

Each subdirectory is one filter:

- `patterns.re` — one regex per line (anchored against the request URI)
- `patterns.txt` — literal substrings, one per line
- `.scenario` — CrowdSec scenario name reported on match
- `.maxfailures` — matches before the scenario triggers
- `.timewindow` — sliding window (seconds)

Filter families:

- `http-*` — scenario-based detection filters (report to CrowdSec on match).
  Covers admin probing, backdoors, WordPress scans, SQLi / XSS probing,
  path traversal, sensitive files, and a handful of targeted CVEs
  (CVE-2021-41773, CVE-2021-44228 log4j, CVE-2021-26086 Jira,
  CVE-2024-0012 PAN-OS, CVE-2024-38475 Apache, CVE-2018-20062 ThinkPHP,
  plus the `http-cve-probing` trending list).
- `url_sensitive`, `url_admin`, `url_api` — generic URL probing filters
  (secret leak paths, admin/panel probing, API endpoint scans).
- `url_scanner` — catch-all signature list for broad scanner detection.
- `urlskip_icons`, `urlskip_robots` — allowlists of URIs that must not
  trigger any filter (favicons/manifests and crawler-standard files).

## `http-cve-probing`

Snapshot of trending-CVE URIs from CrowdSec's
`https://hub-data.crowdsec.net/web/trendy_cves_uris.json`. Refreshed weekly by
the `refresh-cve-probing` GitHub workflow — upstream adds new CVEs regularly.

## License

MIT. Pattern data is imported from crowdsec.net
(Copyright CrowdSecurity, MIT — see
[crowdsecurity/hub](https://github.com/crowdsecurity/hub/blob/master/LICENSE)).
Regex transformations and scenario metadata authored by Linagora.
