const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    _ = b.addModule("pgz", .{
        .source_file = .{ .path = "src/pgz.zig" },
    });

    const lib = b.addStaticLibrary(.{
        .name = "pgz",
        .root_source_file = .{ .path = "src/pgz.zig" },
        .target = target,
        .optimize = optimize,
    });
    lib.install();
}
