# Overview

**pgz** - postgres driver/connector written in Zig (status pre-alpha development)

# TODO

- Optimize allocations (use stack fallback allocator for messages)
- Fix all todos
- Prepared statements
- Connection pools
- Proper decoding/encoding to/of Zig values
- Complete and test in production?
- Reorganize API

# Testing

Create user `testing` with password `testing`.

Create database `testing`.
