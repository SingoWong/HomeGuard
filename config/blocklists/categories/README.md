# Blocklist categories

This directory holds **per-category blocklists** that are referenced from each
device's `hard_blocklists` / `grantable_blocklists` in the SQLite `devices`
table (or, on first boot, in `homeguard.toml [devices.*]`).

The category name comes from the **filename without extension**:
`games.list` ↔ category `games`. So a device with `grantable_blocklists = ["games"]`
will be checked against the contents of `games.list`.

## Two tiers of files

### Auto-generated (not tracked in git)

Built by [`scripts/update-blocklists.sh`](../../../scripts/update-blocklists.sh)
from open-source upstream feeds. These files are listed in
[`.gitignore`](../../../.gitignore) and **must be regenerated after cloning**:

| Category | Source                                  | Approx size | Refresh cadence |
| -------- | --------------------------------------- | ----------- | --------------- |
| porn     | UT1 / `adult`                           | ~300 K domains | weekly       |
| gambling | UT1 / `gambling`                        | ~5 K domains   | weekly       |
| violence | UT1 / `agressif`                        | ~1 K domains   | weekly       |
| drugs    | UT1 / `drogue`                          | ~1 K domains   | weekly       |
| weapons  | UT1 / `dangerous_material`              | ~500 domains   | weekly       |
| piracy   | UT1 / `warez`                           | ~1.5 K domains | weekly       |
| malware  | Hagezi / `tif` (threat-intelligence)    | ~1.4 M domains | daily        |

To populate (or refresh):

```bash
./scripts/update-blocklists.sh                 # all categories
./scripts/update-blocklists.sh -c porn -c malware  # subset
./scripts/update-blocklists.sh --reload        # also kickstart com.homeguard
```

Each file gets a header comment marking when and how it was generated. **Never
edit them by hand** — your changes will be wiped on the next run. To add
manual exceptions or extras, create a separate file under a different name
(e.g. `porn-extra.list`) — it'll be loaded alongside.

### Manually curated (tracked in git)

Files you author by hand. These represent **your policy**, not upstream data,
so they belong in version control. The default examples:

| Category | What goes here |
| -------- | -------------- |
| `games.list`  | Game-related domains you want gated by grants. Upstream blocklists rarely cover these well (and you know your kid's specific games better than a generic feed). |
| `social.list` | Social-media domains. Some overlap with mainstream lists, but the right *granularity* for parental control is personal (do you want to block Discord? Snapchat? TikTok?). |

`.gitignore` allow-lists these specifically; add more allow-list entries there
if you want to track additional hand-curated categories.

## File format

One entry per line. Empty lines and `#` / `!` comments are skipped.

| Pattern                      | Matches                                                    |
| ---------------------------- | ---------------------------------------------------------- |
| `example.com`                | Exact match only (does **not** catch `cdn.example.com`)    |
| `.example.com` or `*.example.com` | Suffix match (covers `example.com` + all subdomains)  |

For nearly all parental-control use cases you want the **suffix form** — porn
and game sites typically serve content from `cdn.*` / `m.*` / `static.*`
subdomains, and an exact-match rule will miss them. `update-blocklists.sh`
already does this transformation when ingesting upstream lists.

## License notes for the auto-generated content

- **UT1 Toulouse blacklists**: free for non-commercial use; commercial use
  requires explicit permission and attribution. See
  <https://dsi.ut-capitole.fr/blacklists/index_en.php>.
- **Hagezi DNS Blocklists**: GPL-3.0. See
  <https://github.com/hagezi/dns-blocklists/blob/main/LICENSE>.

Because of these terms, the auto-generated files are not redistributed in
this repository — each operator pulls from upstream directly via
`update-blocklists.sh`.
