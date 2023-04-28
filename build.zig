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
    b.installArtifact(lib);

    const main_tests = b.addTest(.{
        .root_source_file = .{ .path = "src/pgz.zig" },
        .target = target,
        .optimize = optimize,
    });
    main_tests.emit_docs = .emit;

    const run_main_tests = b.addRunArtifact(main_tests);
    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_main_tests.step);
}
