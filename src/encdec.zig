const std = @import("std");

const hex_charset = "0123456789abcdef";

/// caller owns memory
fn hexEncode(allocator: std.mem.Allocator, string: []const u8) []const u8 {
    var ret = allocator.alloc(u8, 2 + string.len * 2);
    ret[0] = '\\';
    ret[1] = 'x';
    for (string, 0..) |byte, i| {
        ret[(i + 1) * 2 + 0] = hex_charset[byte >> 4];
        ret[(i + 1) * 2 + 1] = hex_charset[byte & 15];
    }
    return ret;
}

/// caller owns memory
pub fn encode(allocator: std.mem.Allocator, value: anytype) ![]const u8 {
    switch (@typeInfo(@TypeOf(value))) {
        .Bool => {
            return try std.fmt.allocPrint(allocator, "{}", .{value});
        },
        .Float, .ComptimeFloat, .Int, .ComptimeInt, .Enum => {
            return try std.fmt.allocPrint(allocator, "{}", .{value});
        },
        .Optional => {
            return encode(allocator, value.?); // value is definitely not null
        },
        .Array => |array| {
            if (array.child == u8) {
                return try allocator.dupe(u8, value);
            }
        },
        .Pointer => |pointer| {
            switch (pointer.size) {
                .One => {
                    if (@typeInfo(pointer.child) == .Array and @typeInfo(pointer.child).Array.child == u8) {
                        return try allocator.dupe(u8, value);
                    }
                },
                .Slice => {
                    if (pointer.child == u8) {
                        return try allocator.dupe(u8, value);
                    }
                },
                else => {},
            }
        },
        else => {},
    }
    return error.EncodeError;
}

/// caller owns memory
pub fn decode(allocator: std.mem.Allocator, string: ?[]const u8, comptime T: type) !T {
    if (string == null and @typeInfo(T) == .Optional) return null;
    if (string == null and @typeInfo(T) != .Optional) return error.DecodeError;

    switch (@typeInfo(T)) {
        .Bool => {
            return string.?[0] == 't';
        },
        .Float, .ComptimeFloat => {
            return try std.fmt.parseFloat(T, string.?);
        },
        .Int, .ComptimeInt => {
            return try std.fmt.parseInt(T, string.?, 10);
        },
        .Optional => |optional| {
            if (string == null) {
                return null;
            } else {
                return try decode(allocator, string, optional.child);
            }
        },
        .Array => |array| {
            if (array.child == u8) {
                return try allocator.dupe(u8, string.?);
            }
        },
        .Pointer => |pointer| {
            switch (pointer.size) {
                .One => {
                    if (@typeInfo(pointer.child) == .Array and @typeInfo(pointer.child).Array.child == u8) {
                        return try allocator.dupe(u8, string.?);
                    }
                },
                .Slice => {
                    if (pointer.child == u8) {
                        return try allocator.dupe(u8, string.?);
                    }
                },
                else => {},
            }
        },
        else => {},
    }
    return error.DecodeError;
}

/// Quotes identifier, caller owns memory
pub fn quoteIdentifier(allocator: std.mem.Allocator, identifier: []const u8) ![]const u8 {
    var buf = try std.ArrayList(u8).initCapacity(allocator, identifier.len + 2);
    defer buf.deinit();
    try buf.append('\"');
    for (0..identifier.len) |i| {
        if (identifier[i] == '\"') {
            try buf.append(identifier[i]);
        }
        try buf.append(identifier[i]);
    }
    try buf.append('\"');
    return try buf.toOwnedSlice();
}

/// Quotes literal, caller owns memory
pub fn quoteLiteral(allocator: std.mem.Allocator, literal: []const u8) ![]const u8 {
    var buf = try std.ArrayList(u8).initCapacity(allocator, literal.len + 2);
    defer buf.deinit();
    var has_backslash = false;
    var i: usize = 0;
    while (i < literal.len) : (i += 1) {
        if (literal[i] == '\\') {
            try buf.append(literal[i]);
            has_backslash = true;
        }
        if (literal[i] == '\'') {
            try buf.append(literal[i]);
        }
        try buf.append(literal[i]);
    }
    if (has_backslash) {
        try buf.insertSlice(0, " E'");
        try buf.append('\'');
    } else {
        try buf.insert(0, '\'');
        try buf.append('\'');
    }
    return try buf.toOwnedSlice();
}

test "quote identifier" {
    var id = try quoteIdentifier(std.testing.allocator, "my_table");
    defer std.testing.allocator.free(id);
    try std.testing.expectEqualStrings("\"my_table\"", id);
}

test "quote literal" {
    var q1 = try quoteLiteral(std.testing.allocator, "hello '' world");
    defer std.testing.allocator.free(q1);
    try std.testing.expectEqualStrings("'hello '''' world'", q1);

    var q2 = try quoteLiteral(std.testing.allocator, "hello \\'\\' world");
    defer std.testing.allocator.free(q2);
    try std.testing.expectEqualStrings(" E'hello \\\\''\\\\'' world'", q2);
}
