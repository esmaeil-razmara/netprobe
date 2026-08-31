# netprobe

A small, dependency-free TCP network probing toolkit with a command-line
interface and a modular web panel.

The CLI covers the two core probes:

- **`scan`** — TCP connect scan of a single host across a set of ports
- **`sweep`** — find which hosts in a subnet accept a connection on a given port

The web panel (`netprobe serve`) adds four more modules on top of those:
**DNS lookup**, **HTTP check**, **TLS certificate**, and **TCP ping** (handshake
latency).

> Only probe hosts and networks you own or are explicitly authorised to test.

## Install

```bash
python -m pip install -e ".[dev]"
```

This requires Python 3.8+ and installs a `netprobe` console command.

## Usage

Scan the common ports on a host:

```bash
netprobe scan scanme.nmap.org -p 22,80,443,8000-8010
```

Sweep a subnet for hosts with port 22 open:

```bash
netprobe sweep 192.168.1.0/24 -p 22
```

Adjust the per-connection timeout (default 1.0s). `--timeout` works either
before or after the subcommand:

```bash
netprobe --timeout 0.5 scan 10.0.0.5
netprobe scan 10.0.0.5 --timeout 0.5
```

You can also run it as a module: `python -m netprobe scan localhost`.

## Web panel

```bash
netprobe serve            # http://127.0.0.1:8765
netprobe serve --port 9000
```

The panel is served by the standard library only (no Flask/Django). It binds to
`127.0.0.1` by default — this is a tool that makes outbound connections on your
behalf, so do not expose it to an untrusted network.

The UI keeps the last-used inputs and the last 10 runs per tool (in the
browser's `localStorage`), has a light/dark toggle, sortable and filterable
result tables, and CSV/JSON export. `#<tool>` in the URL selects a tool.

### Adding a panel module

Every capability in the panel is a file in [`src/netprobe/tools/`](src/netprobe/tools).
To add one, drop in a module that builds a `Tool` and registers it:

```python
# src/netprobe/tools/whois_tool.py
from . import Field, Result, Tool, register

def _run(params):
    host = params["host"]
    # ... do the work; raise ValueError for bad input ...
    return Result(columns=["key", "value"], rows=[["registrar", "..."]],
                  summary="ok", level="ok")  # level: "ok" | "warn" | "error"

register(Tool(
    name="whois",
    title="WHOIS",
    description="Look up registration details for a domain.",
    run=_run,
    fields=[Field("host", "Domain", "text", "", "example.com")],
))
```

The registry auto-discovers it, the API exposes it at `POST /api/tools/whois`,
and the front end renders the form and results table from the field list — no
other files need editing.

## Development

```bash
python -m pytest
```

## License

MIT — see [LICENSE](LICENSE).
