const std = @import("std");

pub const ReadBuffer = struct {
    buf: []const u8,
    pos: u32 = 0,

    pub fn init(buf: []const u8) ReadBuffer {
        return ReadBuffer{ .buf = buf };
    }

    pub fn readInt(self: *ReadBuffer, comptime T: type) T {
        var ret = std.mem.readIntBig(T, self.buf[self.pos..][0..@sizeOf(T)]);
        self.pos += @sizeOf(T);
        return ret;
    }

    pub fn readString(self: *ReadBuffer) []const u8 {
        var start = self.pos;
        while (self.buf[self.pos] != 0 and self.pos < self.buf.len) : (self.pos += 1) {}
        self.pos += 1;
        return self.buf[start .. self.pos - 1];
    }

    pub fn readBytes(self: *ReadBuffer, num: u32) []const u8 {
        var ret = self.buf[self.pos .. self.pos + num];
        self.pos += num;
        return ret;
    }

    pub fn reset(self: *ReadBuffer) void {
        self.pos = 0;
    }
};

pub const WriteBuffer = struct {
    buf: std.ArrayList(u8),

    pub fn init(allocator: std.mem.Allocator) WriteBuffer {
        return WriteBuffer{ .buf = std.ArrayList(u8).init(allocator) };
    }

    pub fn deinit(self: *WriteBuffer) void {
        self.buf.clearAndFree();
    }

    pub fn writeInt(self: *WriteBuffer, comptime T: type, value: T) void {
        self.buf.writer().writeIntBig(T, value) catch {};
    }

    pub fn writeString(self: *WriteBuffer, string: []const u8) void {
        self.buf.writer().writeAll(string) catch {};
        self.buf.writer().writeByte(0) catch {};
    }

    pub fn writeBytes(self: *WriteBuffer, bytes: []const u8) void {
        self.buf.writer().writeAll(bytes) catch {};
    }

    pub fn reset(self: *WriteBuffer) void {
        self.buf.clearRetainingCapacity();
    }
};

pub const Message = struct {
    type: u8,
    len: u32,
    msg: []const u8,

    pub fn read(allocator: std.mem.Allocator, reader: anytype) !Message {
        var type_and_len: [5]u8 = undefined;
        _ = try reader.read(&type_and_len);
        var @"type" = type_and_len[0];
        var len = std.mem.readIntBig(u32, type_and_len[1..][0..4]);
        var msg = try allocator.alloc(u8, len - 4);
        _ = try reader.read(msg);
        return Message{ .type = @"type", .len = len, .msg = msg };
    }

    pub fn free(self: *Message, allocator: std.mem.Allocator) void {
        allocator.free(self.msg);
    }
};

const RowHeader = struct {
    name: []const u8,
    type: u32,
    binary: bool,
};

const Row = struct {
    value: ?[]const u8 = null,
};

pub const Connection = struct {
    allocator: std.mem.Allocator,
    stream: std.net.Stream,
    buffer: WriteBuffer,

    pub fn init(allocator: std.mem.Allocator) Connection {
        return Connection{
            .allocator = allocator,
            .stream = undefined,
            .buffer = WriteBuffer.init(allocator),
        };
    }

    // TODO: handle all msg types
    pub fn connect(self: *Connection, dsn: std.Uri) !void {
        var address = try std.net.Address.parseIp(dsn.host orelse "127.0.0.1", dsn.port orelse 5432);
        self.stream = try std.net.tcpConnectToAddress(address);
        try self.startup(dsn.user orelse "postgres", dsn.path[1..]);
        while (true) {
            var msg = try Message.read(self.allocator, self.stream.reader());
            defer msg.free(self.allocator);
            switch (msg.type) {
                'R' => try self.handleAuth(msg, dsn.user orelse "postgres", dsn.password orelse ""),
                'K' => {},
                'S' => {},
                'Z' => return,
                else => return error.UnexpectedMessage,
            }
        }
    }

    pub fn disconnect(self: *Connection) void {
        self.stream.close();
    }

    fn startup(self: *Connection, user: []const u8, database: []const u8) !void {
        self.buffer.reset();
        self.buffer.writeInt(u32, 196608);
        self.buffer.writeString("user");
        self.buffer.writeString(user);
        self.buffer.writeString("database");
        self.buffer.writeString(database);
        self.buffer.writeInt(u8, 0);
        try self.stream.writer().writeIntBig(u32, @intCast(u32, self.buffer.buf.items.len + 4));
        try self.stream.writeAll(self.buffer.buf.items);
    }

    // TODO: other auth methods
    fn handleAuth(self: *Connection, msg: Message, user: []const u8, password: []const u8) !void {
        switch (msg.type) {
            'R' => {
                var buffer = ReadBuffer.init(msg.msg);
                var password_type = buffer.readInt(u32);
                switch (password_type) {
                    0 => {},
                    5 => {
                        var static_buffer: [1024]u8 = undefined;
                        if (user.len + password.len > 1024) return error.OutOfMemory;
                        var salt = buffer.readBytes(4);
                        var user_password = try std.fmt.bufPrint(&static_buffer, "{s}{s}", .{ password, user });
                        var hash = md5(user_password);
                        var salted_hash = try std.fmt.bufPrint(&static_buffer, "{s}{s}", .{ &hash, salt });
                        var final_hash = "md5" ++ md5(salted_hash);
                        self.buffer.reset();
                        self.buffer.writeString(final_hash);
                        try self.stream.writer().writeByte('p');
                        try self.stream.writer().writeIntBig(u32, @intCast(u32, self.buffer.buf.items.len + 4));
                        try self.stream.writeAll(self.buffer.buf.items);

                        var check_msg = try Message.read(self.allocator, self.stream.reader());
                        defer check_msg.free(self.allocator);
                        var check_buffer = ReadBuffer.init(check_msg.msg);
                        var status = check_buffer.readInt(u32);
                        if (status != 0) return error.AuthenticationError;
                    },
                    else => return error.UnsupportedAuthentication,
                }
            },
            else => return error.UnexpectedMessage,
        }
    }

    pub fn simpleExec(self: *Connection, sql: []const u8) !void {
        self.buffer.reset();
        self.buffer.writeString(sql);
        try self.stream.writer().writeByte('Q');
        try self.stream.writer().writeIntBig(u32, @intCast(u32, self.buffer.buf.items.len + 4));
        try self.stream.writeAll(self.buffer.buf.items);

        while (true) {
            var msg = try Message.read(self.allocator, self.stream.reader());
            defer msg.free(self.allocator);
            switch (msg.type) {
                'E' => return error.SqlExecuteError,
                'Z' => break,
                else => {},
            }
        }
    }

    /// caller owns memory, free with freeSimpleQuery
    pub fn simpleQuery(self: *Connection, sql: []const u8, comptime T: type) ![]T {
        self.buffer.reset();
        self.buffer.writeString(sql);
        try self.stream.writer().writeByte('Q');
        try self.stream.writer().writeIntBig(u32, @intCast(u32, self.buffer.buf.items.len + 4));
        try self.stream.writeAll(self.buffer.buf.items);

        // TODO: do we need this headers? can we use struct order?
        var row_headers = try std.ArrayListUnmanaged(RowHeader).initCapacity(self.allocator, 10);
        defer {
            for (row_headers.items) |row_header| {
                self.allocator.free(row_header.name);
            }
            row_headers.clearAndFree(self.allocator);
        }

        var rows = try std.ArrayListUnmanaged(Row).initCapacity(self.allocator, 10);
        defer rows.clearAndFree(self.allocator);

        var result = try std.ArrayListUnmanaged(T).initCapacity(self.allocator, 10);
        defer result.deinit(self.allocator);

        while (true) {
            var msg = try Message.read(self.allocator, self.stream.reader());
            defer msg.free(self.allocator);
            switch (msg.type) {
                'E' => return error.SqlQueryError,
                'Z' => break,
                'T' => {
                    var buffer = ReadBuffer.init(msg.msg);
                    var num_rows = buffer.readInt(u16);
                    try row_headers.ensureTotalCapacity(self.allocator, num_rows);
                    var i: usize = 0;
                    while (i < num_rows) : (i += 1) {
                        var name = try self.allocator.dupe(u8, buffer.readString());
                        _ = buffer.readInt(u32);
                        _ = buffer.readInt(u16);
                        var data_type = buffer.readInt(u32);
                        _ = buffer.readInt(u16);
                        _ = buffer.readInt(u32);
                        var text_or_binary = buffer.readInt(u16);
                        try row_headers.append(self.allocator, RowHeader{
                            .name = name,
                            .type = data_type,
                            .binary = text_or_binary == 1,
                        });
                    }
                },
                'D' => {
                    var buffer = ReadBuffer.init(msg.msg);
                    var num_rows = buffer.readInt(u16);
                    try rows.ensureTotalCapacity(self.allocator, num_rows);
                    var i: usize = 0;
                    while (i < num_rows) : (i += 1) {
                        var len = buffer.readInt(u32);
                        if (len == -1) {
                            try rows.append(self.allocator, Row{ .value = null });
                        } else {
                            var buf = buffer.readBytes(len);
                            try rows.append(self.allocator, Row{ .value = buf });
                        }
                    }
                    // TODO: proper decoding
                    var row: T = undefined;
                    inline for (@typeInfo(T).Struct.fields) |field, j| {
                        @field(row, field.name) = try self.allocator.dupe(u8, rows.items[j].value.?);
                    }
                    try result.append(self.allocator, row);
                },
                else => {},
            }
        }
        return try result.toOwnedSlice(self.allocator);
    }

    pub fn freeSimpleQuery(self: *Connection, slice: anytype) void {
        for (slice) |v| {
            inline for (@typeInfo(@TypeOf(v)).Struct.fields) |field| {
                self.allocator.free(@field(v, field.name));
            }
        }
        self.allocator.free(slice);
    }

    pub fn deinit(self: *Connection) void {
        self.buffer.deinit();
    }
};

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

// TODO: optimize
pub fn md5(s: []const u8) [32]u8 {
    var ret: [32]u8 = undefined;
    var digest: [16]u8 = undefined;
    std.crypto.hash.Md5.hash(s, &digest, .{});
    for (digest) |n, i| {
        _ = std.fmt.bufPrint(ret[i * 2 ..], "{x:0>2}", .{n}) catch unreachable;
    }
    return ret;
}

test "connect" {
    var conn = Connection.init(std.testing.allocator);
    defer conn.deinit();
    try conn.connect(try std.Uri.parse("postgres://testing:testing@127.0.0.1:5432/testing"));
    defer conn.disconnect();
}

test "simple exec" {
    var conn = Connection.init(std.testing.allocator);
    defer conn.deinit();
    try conn.connect(try std.Uri.parse("postgres://testing:testing@127.0.0.1:5432/testing"));
    defer conn.disconnect();
    try conn.simpleExec("SELECT 1;");
}

test "simple query" {
    var conn = Connection.init(std.testing.allocator);
    defer conn.deinit();
    try conn.connect(try std.Uri.parse("postgres://testing:testing@127.0.0.1:5432/testing"));
    defer conn.disconnect();
    var queryResult = try conn.simpleQuery("SELECT 1;", struct { result: []const u8 });
    defer conn.freeSimpleQuery(queryResult);
    try std.testing.expectEqual(@as(usize, 1), queryResult.len);
    try std.testing.expectEqualStrings("1", queryResult[0].result);
}

test "read buffer" {
    const data = [_]u8{ 0, 0, 0, 5, 0, 0, 0, 12, 72, 101, 108, 108, 111, 0, 119, 111, 114, 108, 100, 0 };
    var buf = ReadBuffer.init(&data);
    try std.testing.expectEqual(@as(u32, 5), buf.readInt(u32));
    try std.testing.expectEqual(@as(u32, 12), buf.readInt(u32));
    try std.testing.expectEqualStrings("Hello", buf.readString());
    try std.testing.expectEqualStrings("world", buf.readString());
}

test "write buffer" {
    const data = [_]u8{ 0, 0, 0, 5, 0, 0, 0, 12, 72, 101, 108, 108, 111, 0, 119, 111, 114, 108, 100, 0 };
    var buf = WriteBuffer.init(std.testing.allocator);
    defer buf.deinit();
    buf.writeInt(u32, 5);
    buf.writeInt(u32, 12);
    buf.writeString("Hello");
    buf.writeString("world");
    try std.testing.expectEqualSlices(u8, &data, buf.buf.items);
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
