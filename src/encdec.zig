const std = @import("std");

const hex_charset = "0123456789abcdef";

/// caller owns memory
fn hexEncode(allocator: std.mem.Allocator, string: []const u8) []const u8 {
    var ret = allocator.alloc(u8, 2 + string.len * 2);
    ret[0] = '\\';
    ret[1] = 'x';
    for (string) |byte, i| {
        ret[(i + 1) * 2 + 0] = hex_charset[byte >> 4];
        ret[(i + 1) * 2 + 1] = hex_charset[byte & 15];
    }
    return ret;
}

/// caller owns memory
pub fn encode(allocator: std.mem.Allocator, value: anytype) ![]const u8 {
    switch (@TypeOf(value)) {
        bool => {
            return try std.fmt.allocPrint(allocator, "{}", .{value});
        },
        comptime_int, i8, u8, i16, u16, i32, u32, i64, u64, usize, comptime_float, f32, f64 => {
            return try std.fmt.allocPrint(allocator, "{d}", .{value});
        },
        []const u8 => {
            return hexEncode(allocator, value);
        },
        else => {
            return error.EncodeError;
        },
    }
}

/// caller owns memory
pub fn decode(allocator: std.mem.Allocator, string: ?[]const u8, comptime T: type) !T {
    if (string) |s| {
        switch (T) {
            bool => {
                return s[0] == 't';
            },
            []const u8 => {
                return try allocator.dupe(u8, s);
            },
            i8, u8, i16, u16, i32, u32, i64, u64, usize => {
                return try std.fmt.parseInt(T, s, 10);
            },
            f32, f64 => {
                return try std.fmt.parseFloat(T, s);
            },
            else => {
                return error.DecodeError;
            },
        }
    } else {
        if (@typeInfo(T) == .Optional) {
            return null;
        } else {
            return error.DecodeError;
        }
    }
}

/// caller owns memory
pub fn quoteIdentifier(allocator: std.mem.Allocator, identifier: []const u8) ![]const u8 {
    var buf = try std.ArrayList(u8).initCapacity(allocator, identifier.len + 2);
    defer buf.deinit();
    try buf.append('\"');
    var i: usize = 0;
    while (i < identifier.len) : (i += 1) {
        if (identifier[i] == '\"') {
            try buf.append(identifier[i]);
        }
        try buf.append(identifier[i]);
    }
    try buf.append('\"');
    return try buf.toOwnedSlice();
}

/// caller owns memory
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
