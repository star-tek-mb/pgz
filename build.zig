const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mbedtls_dep = b.dependency("mbedtls", .{
        .target = target,
        .optimize = optimize,
    });

    b.addModule(.{
        .name = "pgz",
        .source_file = .{ .path = "src/pgz.zig" },
    });

    const lib = b.addStaticLibrary(.{
        .name = "pgz",
        .root_source_file = .{ .path = "src/pgz.zig" },
        .target = target,
        .optimize = optimize,
    });
    lib.install();

    const main_tests = b.addTest(.{
        .root_source_file = .{ .path = "src/pgz.zig" },
        .target = target,
        .optimize = optimize,
    });
    main_tests.linkLibrary(mbedtls_dep.artifact("mbedtls"));
    main_tests.emit_docs = .emit;

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&main_tests.step);
}
