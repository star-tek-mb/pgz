# Overview

![](https://img.shields.io/github/actions/workflow/status/star-tek-mb/pgz/ci.yml)
![](https://img.shields.io/badge/version-0.0.1-red)
![](https://img.shields.io/github/license/star-tek-mb/pgz)
![https://pgz.decoy.uz](https://img.shields.io/badge/docs-passing-green)

**pgz** - postgres driver/connector written in Zig (status pre-alpha development)

# Package manager ready

Add following lines to your `build.zig.zon` dependencies:
```zig
.pgz = .{
    .url = "git+https://github.com/star-tek-mb/pgz#master",
}
```

Run `zig build` then obtain hash of the package and insert it to `build.zig.zon`.

Then you can use it as a library. Add following lines to `build.zig`:

```zig
const pgz_dep = b.dependency("pgz", .{ .target = target, .optimize = optimize });

exe.addModule("pgz", pgz_dep.module("pgz"));
```

# Example

```zig
const std = @import("std");
const Connection = @import("pgz").Connection;

pub fn main() !void {
    var dsn = try std.Uri.parse("postgres://testing:testing@localhost:5432/testing");
    var connection = try Connection.init(std.heap.page_allocator, dsn);
    defer connection.deinit();
    var result = try connection.query("SELECT 1 as number;", struct { number: ?[]const u8 });
    defer result.deinit();

    try connection.exec("CREATE TABLE users(name text not null);");
    defer connection.exec("DROP TABLE users;") catch {};
    var stmt = try connection.prepare("INSERT INTO users(name) VALUES($1);");
    defer stmt.deinit();
    try stmt.exec(.{"hello"});
    try stmt.exec(.{"world"});

    try std.io.getStdOut().writer().print("number = {s}\n", .{result.data[0].number.?});
}
```

# TODOs

- Optimize allocations (use stack fallback allocator for messages)
- Fix all todos in code
- Connection pools (do we need them?)
- Complete and test in production?

# Testing

Create user `testing` with password `testing`.

Create database `testing`.

Run `zig build test`
