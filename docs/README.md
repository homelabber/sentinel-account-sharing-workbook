# Screenshot sources

The images in `img/` are rendered from the HTML mockups in `src/`.

## Why mockups rather than live captures

Screenshots of a real Microsoft Sentinel instance would embed real tenant data —
account names, IP addresses, physical locations, department structure — into a
public repository. That is not an acceptable trade for documentation.

**Every value shown is fabricated.** Addresses use the
[RFC 5737](https://datatracker.ietf.org/doc/html/rfc5737) documentation ranges
(`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and domains use
[RFC 2606](https://datatracker.ietf.org/doc/html/rfc2606) reserved names.

The layout, typography, colour treatment, column sets and panel copy match the
real workbook — the synthetic part is the data, not the interface.

## Regenerating

```powershell
# serve the mockups
cd docs/src
python -m http.server 8731 --bind 127.0.0.1

# then capture each page at 1620px wide, full page, device scale
```

The mockups are plain HTML with a shared `theme.css`. Edit the tables to change
the illustrated scenario.
