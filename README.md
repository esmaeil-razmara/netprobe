# netprobe

A small, dependency-free TCP network probing toolkit with a command-line
interface. It does two things:

- **`scan`** — TCP connect scan of a single host across a set of ports
- **`sweep`** — find which hosts in a subnet accept a connection on a given port

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

## Development

```bash
python -m pytest
```

## License

MIT — see [LICENSE](LICENSE).
