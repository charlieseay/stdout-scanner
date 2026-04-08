# stdout-scanner

Docker sidecar that discovers your infrastructure and pushes it to [StdOut](https://stdout.seayniclabs.com).

## Quick Start

```bash
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  ghcr.io/charlieseay/stdout-scanner \
  --token YOUR_TOKEN \
  --url https://stdout.seayniclabs.com
```

## What it discovers

- Docker containers: name, image, ports, status, health, networks, compose project
- Volume mount paths
- Environment variable **names** (never values)
- Restart policies
- Host: OS, CPU, memory, disk
- Docker networks: name, driver, subnet, connected containers

## What it never collects

- Environment variable values
- File contents
- Secrets, credentials, or tokens
- Anything outside Docker

## Options

```
--token     StdOut API token (required for push)
--url       StdOut instance URL (required for push)
--output    json or markdown (print to stdout instead of pushing)
--full      Enable all detection modules
--scan-sources Detect installed tooling (Prometheus, Trivy, Loki, etc.)
--skip-host Skip host info collection
--dry-run   Discover but don't push
--version   Print version
```

## Data source auto-registration

When `--scan-sources` is enabled, scanner includes a `data_sources` block in
the payload. StdOut uses this to auto-register supported sources during
`/app/api/stacks/import` (currently Prometheus), so metrics enrichment can work
without manual setup.

## Local output

```bash
# JSON to stdout
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock:ro \
  ghcr.io/charlieseay/stdout-scanner --output json

# Markdown to stdout
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock:ro \
  ghcr.io/charlieseay/stdout-scanner --output markdown
```

## Build from source

```bash
go build -o stdout-scanner ./cmd/scanner
```

## License

Proprietary. Part of the StdOut product by [Seaynic Labs](https://seayniclabs.com).
