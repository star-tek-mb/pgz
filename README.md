# Overview

![](https://img.shields.io/github/actions/workflow/status/star-tek-mb/pgz/ci.yml)
![](https://img.shields.io/badge/version-0.0.1-red)
![](https://img.shields.io/github/license/star-tek-mb/pgz)

**pgz** - postgres driver/connector written in Zig (status pre-alpha development)

# Example

```zig
const std = @import("std");
const Connection = @import("pgz.zig").Connection;

pub fn main() !void {
    var connection = try Connection.init(std.heap.page_allocator, try std.Uri.parse("postgres://testing:testing@localhost:5432/testing"));
    defer connection.deinit();
    var result = try connection.query("SELECT 1 as number;", struct { number: u8 });
    defer result.deinit();

    try std.io.getStdOut().writer().print("number = {d}\n", .{result.data[0].number});
}
```

# TODOs

- Optimize allocations (use stack fallback allocator for messages)
- Fix all todos in code
- Connection pools (do we need them?)
- Complete and test in production?
- Log errors? Provide diagnostics?

# Testing

Create user `testing` with password `testing`.

Create database `testing`.
