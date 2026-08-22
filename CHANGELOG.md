# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-08-22

### Added
- TCP connect scanning engine with configurable timeout, concurrency, and retries.
- Multi-target input: single host, comma-separated list, CIDR network, or file.
- Service identification from a port map plus banner-based fingerprinting.
- Advisory notes for commonly misconfigured services.
- Optional per-second rate limiting.
- Console, JSON, CSV, and self-contained HTML reporting.
- Test suite covering parsing, service identification, resilience, and live scans.
