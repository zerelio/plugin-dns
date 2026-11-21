# Zerelio DNS Plugin

Discovers DNS zones and records via zone transfer or recursive resolution, and streams them into the Zerelio knowledge graph.

## What It Discovers

| Resource type    | Description                                              |
|------------------|----------------------------------------------------------|
| `dns.zone`       | DNS zones                                                |
| `dns.record`     | Resource records: A, AAAA, CNAME, MX, TXT, NS, SRV      |

Discovery uses AXFR zone transfer when the target nameserver permits it; otherwise it falls back to recursive resolution of records within each configured zone.

## Configuration

| Environment variable | Required | Description                                                  |
|----------------------|----------|--------------------------------------------------------------|
| `DNS_SERVER`         | No       | Nameserver to query (default: `8.8.8.8:53`)                  |
| `DNS_ZONES`          | Yes      | Comma-separated list of zones to discover, e.g. `example.com,internal.corp` |

## Adding to a Zerelio Scope

```json
{
  "scope_name": "My DNS Zones",
  "plugin_name": "dns",
  "config": {
    "server": "ns1.example.com",
    "zones": "example.com,internal.corp"
  },
  "schedule": "@every 6h"
}
```

## Part of Zerelio

This plugin is part of the [Zerelio](https://github.com/zerelio/knowledge) infrastructure knowledge graph platform.
