const std = @import("std");
const encdec = @import("encdec.zig");
const messaging = @import("messaging.zig");
const auth = @import("auth.zig");

pub const quoteIdentifier = encdec.quoteIdentifier;
pub const quoteLiteral = encdec.quoteLiteral;
const ReadBuffer = messaging.ReadBuffer;
const WriteBuffer = messaging.WriteBuffer;
const Message = messaging.Message;

const Error = struct {
    severity: [5]u8 = undefined,
    code: [5]u8 = undefined,
    message: [128]u8 = undefined,
    length: u32 = 0,

    pub const Severity = enum {
        ERROR,
        FATAL,
        PANIC,
    };

    pub fn getSeverity(self: *const Error) Severity {
        return std.meta.stringToEnum(Severity, self.severity[0..]).?;
    }

    pub fn getCode(self: *const Error) []const u8 {
        return self.code[0..];
    }

    pub fn getMessage(self: *const Error) []const u8 {
        return self.message[0..self.length];
    }
};

const RowHeader = struct {
    name: []const u8,
    type: u32,
    binary: bool,
};

pub fn QueryResult(comptime T: type) type {
    return struct {
        allocator: std.mem.Allocator,
        data: []T,
        affectedRows: u32,

        pub fn deinit(self: *@This()) void {
            for (self.data) |row| {
                inline for (@typeInfo(T).Struct.fields) |field| {
                    if (@typeInfo(field.type) == .Pointer) {
                        self.allocator.free(@field(row, field.name));
                    }
                    if (@typeInfo(field.type) == .Optional and @typeInfo(@typeInfo(field.type).Optional.child) == .Pointer and @field(row, field.name) != null) {
                        self.allocator.free(@field(row, field.name).?);
                    }
                }
            }
            self.allocator.free(self.data);
        }
    };
}

pub const Connection = struct {
    allocator: std.mem.Allocator,
    stream: std.net.Stream,
    statement_count: u32 = 0,
    @"error": ?Error = null,

    pub fn init(allocator: std.mem.Allocator, dsn: std.Uri) !Connection {
        var connection = Connection{
            .allocator = allocator,
            .stream = undefined,
        };
        connection.stream = try std.net.tcpConnectToHost(allocator, dsn.host orelse "localhost", dsn.port orelse 5432);
        try connection.startup(dsn.user orelse "postgres", dsn.path[1..]);
        while (true) {
            var msg = try Message.read(allocator, connection.stream.reader());
            defer msg.free(allocator);
            switch (msg.type) {
                'R' => try connection.handleAuth(msg, dsn.user orelse "postgres", dsn.password orelse ""),
                'K' => {}, // TODO: handle
                'S' => {}, // TODO: handle
                'Z' => break,
                else => return error.UnexpectedMessage,
            }
        }
        return connection;
    }

    pub fn getLastError(self: *Connection) Error {
        return self.@"error".?;
    }

    pub fn exec(self: *Connection, sql: []const u8) !void {
        var wb = try WriteBuffer.init(self.allocator, 'Q');
        defer wb.deinit();
        wb.writeString(sql);
        try wb.send(self.stream);

        while (true) {
            var msg = try Message.read(self.allocator, self.stream.reader());
            defer msg.free(self.allocator);
            switch (msg.type) {
                'E' => {
                    self.parseError(msg);
                    return error.SqlExecuteError;
                },
                'Z' => break,
                else => {},
            }
        }
    }

    /// caller owns memory, release memory with `result.deinit()` function
    pub fn query(self: *Connection, sql: []const u8, comptime T: type) !QueryResult(T) {
        var wb = try WriteBuffer.init(self.allocator, 'Q');
        defer wb.deinit();
        wb.writeString(sql);
        try wb.send(self.stream);
        return self.fetchRows(T);
    }

    pub fn prepare(self: *Connection, sql: []const u8) !Statement {
        var name_buffer: [10]u8 = undefined; // 4294967295 - max value - length 10
        var name = try std.fmt.bufPrint(&name_buffer, "{d}", .{self.statement_count});
        self.statement_count += 1;

        var wb = try WriteBuffer.init(self.allocator, 'P');
        defer wb.deinit();
        wb.writeString(name);
        wb.writeString(sql);
        wb.writeInt(u16, 0);
        wb.next('D');
        wb.writeInt(u8, 'S');
        wb.writeString(name);
        wb.next('S');
        try wb.send(self.stream);

        while (true) {
            var msg = try Message.read(self.allocator, self.stream.reader());
            defer msg.free(self.allocator);
            switch (msg.type) {
                'E' => {
                    self.parseError(msg);
                    return error.SqlPrepareError;
                },
                'Z' => break,
                else => {},
            }
        }

        return Statement{ .connection = self.*, .statement = self.statement_count - 1 };
    }

    pub fn deinit(self: *Connection) void {
        self.notifyClose() catch {};
        self.stream.close();
    }

    fn startup(self: *Connection, user: []const u8, database: []const u8) !void {
        var wb = try WriteBuffer.init(self.allocator, null);
        defer wb.deinit();
        wb.writeInt(u32, 196608);
        wb.writeString("user");
        wb.writeString(user);
        wb.writeString("database");
        wb.writeString(database);
        wb.writeInt(u8, 0);
        try wb.send(self.stream);
    }

    fn handleAuth(self: *Connection, msg: Message, user: []const u8, password: []const u8) !void {
        if (msg.type != 'R') return error.UnexpectedMessage;

        var buffer = ReadBuffer.init(msg.msg);
        var password_type = buffer.readInt(u32);
        switch (password_type) {
            0 => {},
            5 => {
                var salt = buffer.readBytes(4);

                var md5 = auth.md5(user, password, salt);
                var wb = try WriteBuffer.init(self.allocator, 'p');
                defer wb.deinit();
                wb.writeString(&md5);
                try wb.send(self.stream);

                var check_msg = try Message.read(self.allocator, self.stream.reader());
                defer check_msg.free(self.allocator);
                var check_buffer = ReadBuffer.init(check_msg.msg);
                var status = check_buffer.readInt(u32);
                if (status != 0) return error.AuthenticationError;
            },
            10 => {
                var scram = auth.Scram.init(password);

                var wb = try WriteBuffer.init(self.allocator, 'p');
                defer wb.deinit();
                scram.state.writeTo(&wb);
                try wb.send(self.stream);

                var server_first = try Message.read(self.allocator, self.stream.reader());
                defer server_first.free(self.allocator);
                if (server_first.type != 'R') return error.AuthenticationError;
                scram.update(server_first.msg[4..]) catch return error.AuthenticationError;

                wb.reset('p');
                scram.state.writeTo(&wb);
                try wb.send(self.stream);

                var server_final = try Message.read(self.allocator, self.stream.reader());
                defer server_final.free(self.allocator);
                if (server_final.type != 'R') return error.AuthenticationError;
                scram.finish(server_final.msg[4..]) catch return error.AuthenticationError;
            },
            else => return error.AuthenticationError, // TODO: handle other auth methods
        }
    }

    fn fetchRows(self: *Connection, comptime T: type) !QueryResult(T) {
        var affectedRows: u32 = 0;

        var row_headers = try std.ArrayListUnmanaged(RowHeader).initCapacity(self.allocator, 10);
        defer {
            for (row_headers.items) |row_header| {
                self.allocator.free(row_header.name);
            }
            row_headers.clearAndFree(self.allocator);
        }

        var result = try std.ArrayListUnmanaged(T).initCapacity(self.allocator, 10);
        defer result.deinit(self.allocator);

        while (true) {
            var msg = try Message.read(self.allocator, self.stream.reader());
            defer msg.free(self.allocator);
            switch (msg.type) {
                'C' => {
                    if (msg.len > 4) {
                        var buffer = ReadBuffer.init(msg.msg);
                        affectedRows = parseAffectedRows(buffer.readString());
                    }
                },
                'E' => {
                    self.parseError(msg);
                    return error.SqlQueryError;
                },
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
                    if (num_rows > @typeInfo(T).Struct.fields.len) return error.ScanMismatch;

                    var scanned: usize = 0;
                    var row: T = undefined;
                    var i: usize = 0;

                    while (i < num_rows) : (i += 1) {
                        var len = buffer.readInt(u32);
                        var value: ?[]const u8 = undefined;
                        if (len == @truncate(u32, -1)) {
                            value = null;
                        } else {
                            value = buffer.readBytes(len);
                        }

                        if (@typeInfo(T).Struct.is_tuple) {
                            inline for (@typeInfo(T).Struct.fields) |field, j| {
                                if (i == j) {
                                    @field(row, field.name) = try encdec.decode(self.allocator, value, field.type);
                                    scanned += 1;
                                }
                            }
                        } else {
                            inline for (@typeInfo(T).Struct.fields) |field, j| {
                                if (i == j and std.mem.eql(u8, row_headers.items[i].name, field.name)) {
                                    @field(row, field.name) = try encdec.decode(self.allocator, value, field.type);
                                    scanned += 1;
                                }
                            }
                        }
                    }

                    if (scanned != @typeInfo(T).Struct.fields.len) return error.ScanMismatch;
                    try result.append(self.allocator, row);
                },
                else => {},
            }
        }
        return QueryResult(T){
            .allocator = self.allocator,
            .data = try result.toOwnedSlice(self.allocator),
            .affectedRows = affectedRows,
        };
    }

    fn parseError(self: *Connection, msg: Message) void {
        self.@"error" = Error{};

        var rb = ReadBuffer.init(msg.msg);
        var code = rb.readInt(u8);
        while (code != 0) : (code = rb.readInt(u8)) {
            switch (code) {
                'S', 'V' => {
                    std.mem.copy(u8, self.@"error".?.severity[0..], rb.readString());
                },
                'C' => {
                    std.mem.copy(u8, self.@"error".?.code[0..], rb.readString());
                },
                'M' => {
                    var message = rb.readString();
                    if (message.len > 256) {
                        self.@"error".?.length = 0;
                    } else {
                        self.@"error".?.length = @intCast(u32, message.len);
                        std.mem.copy(u8, self.@"error".?.message[0..], message);
                    }
                },
                else => {
                    _ = rb.readString();
                },
            }
        }
    }

    fn notifyClose(self: *Connection) !void {
        var wb = try WriteBuffer.init(self.allocator, 'X');
        defer wb.deinit();
        try wb.send(self.stream);
    }
};

pub const Statement = struct {
    connection: Connection,
    statement: u32,

    pub fn deinit(self: *Statement) void {
        var name_buffer: [10]u8 = undefined; // 4294967295 - max value - length 10
        var name = std.fmt.bufPrint(&name_buffer, "{d}", .{self.statement}) catch return;
        var buffer = WriteBuffer.init(self.connection.allocator, 'C') catch return;
        defer buffer.deinit();
        buffer.writeInt(u8, 'C');
        buffer.writeString(name);
        buffer.next('S');
        buffer.send(self.connection.stream) catch return;
    }

    pub fn exec(self: *Statement, args: anytype) !void {
        try self.sendExec(args);

        while (true) {
            var msg = try Message.read(self.connection.allocator, self.connection.stream.reader());
            defer msg.free(self.connection.allocator);
            switch (msg.type) {
                'E' => {
                    self.connection.parseError(msg);
                    return error.SqlExecuteError;
                },
                'Z' => break,
                else => {},
            }
        }
    }

    pub fn query(self: *Statement, comptime T: type, args: anytype) !QueryResult(T) {
        try self.sendExec(args);
        return try self.connection.fetchRows(T);
    }

    fn sendExec(self: *Statement, args: anytype) !void {
        var name_buffer: [10]u8 = undefined; // 4294967295 - max value - length 10
        var name = try std.fmt.bufPrint(&name_buffer, "{d}", .{self.statement});

        var wb = try WriteBuffer.init(self.connection.allocator, 'B');
        defer wb.deinit();
        wb.writeInt(u8, 0);
        wb.writeString(name);
        wb.writeInt(u16, 0);
        wb.writeInt(u16, args.len);
        inline for (@typeInfo(@TypeOf(args)).Struct.fields) |field| {
            if ((@typeInfo(field.type) == .Optional or @typeInfo(field.type) == .Null) and @field(args, field.name) == null) {
                wb.writeInt(u32, @truncate(u32, -1));
            } else {
                var encoded = try encdec.encode(self.connection.allocator, @field(args, field.name));
                defer self.connection.allocator.free(encoded);
                wb.writeInt(u32, @intCast(u32, encoded.len));
                wb.writeBytes(encoded);
            }
        }
        wb.writeInt(u16, 0);
        wb.next('E');
        wb.writeInt(u8, 0);
        wb.writeInt(u32, 0);
        wb.next('S');
        try wb.send(self.connection.stream);
    }
};

fn parseAffectedRows(command: []const u8) u32 {
    if (command.len == 0) return 0;

    var tokenizer = std.mem.tokenize(u8, command, " ");
    _ = tokenizer.next(); // INSERT or SELECT
    var second = tokenizer.next(); // 0 or affected rows
    var maybe_last = tokenizer.next(); // affected rows or EOF
    if (maybe_last) |last| {
        return std.fmt.parseInt(u32, last, 10) catch 0;
    } else {
        return std.fmt.parseInt(u32, second.?, 10) catch 0;
    }
}

test "connect" {
    var conn = try Connection.init(std.testing.allocator, try std.Uri.parse("postgres://testing:testing@localhost:5432/testing"));
    defer conn.deinit();
}

test "exec" {
    var conn = try Connection.init(std.testing.allocator, try std.Uri.parse("postgres://testing:testing@localhost:5432/testing"));
    defer conn.deinit();
    try conn.exec("SELECT 1;");
}

test "query" {
    var conn = try Connection.init(std.testing.allocator, try std.Uri.parse("postgres://testing:testing@localhost:5432/testing"));
    defer conn.deinit();
    var result = try conn.query("SELECT 1;", struct { u8 });
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 1), result.data.len);
    try std.testing.expectEqual(@as(u8, 1), result.data[0].@"0");
}

test "query named" {
    var conn = try Connection.init(std.testing.allocator, try std.Uri.parse("postgres://testing:testing@localhost:5432/testing"));
    defer conn.deinit();
    var result = try conn.query("SELECT 1 as number;", struct { number: u8 });
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 1), result.data.len);
    try std.testing.expectEqual(@as(u8, 1), result.data[0].number);
}

test "query multiple rows" {
    var conn = try Connection.init(std.testing.allocator, try std.Uri.parse("postgres://testing:testing@localhost:5432/testing"));
    defer conn.deinit();
    var result = try conn.query("VALUES (1,2,3), (4,5,6), (7,8,9);", struct { u8, u8, u8 });
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 3), result.data.len);
    try std.testing.expectEqual(@as(u8, 1), result.data[0].@"0");
    try std.testing.expectEqual(@as(u8, 4), result.data[1].@"0");
    try std.testing.expectEqual(@as(u8, 7), result.data[2].@"0");
}

test "query multiple named rows" {
    var conn = try Connection.init(std.testing.allocator, try std.Uri.parse("postgres://testing:testing@localhost:5432/testing"));
    defer conn.deinit();
    var result = try conn.query("VALUES (1,2,3), (4,5,6), (7,8,9);", struct { column1: u8, column2: u8, column3: u8 });
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 3), result.data.len);
    try std.testing.expectEqual(@as(u8, 1), result.data[0].column1);
    try std.testing.expectEqual(@as(u8, 5), result.data[1].column2);
    try std.testing.expectEqual(@as(u8, 9), result.data[2].column3);
}

test "prepare" {
    var conn = try Connection.init(std.testing.allocator, try std.Uri.parse("postgres://testing:testing@localhost:5432/testing"));
    defer conn.deinit();
    var stmt = try conn.prepare("SELECT 1 + $1;");
    defer stmt.deinit();
    var result = try stmt.query(struct { []const u8 }, .{2});
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 1), result.data.len);
    try std.testing.expectEqualStrings("3", result.data[0].@"0");
}

test "prepare exec many times" {
    var conn = try Connection.init(std.testing.allocator, try std.Uri.parse("postgres://testing:testing@localhost:5432/testing"));
    defer conn.deinit();
    var stmt = try conn.prepare("SELECT 1 + $1;");
    defer stmt.deinit();
    try stmt.exec(.{1});
    try stmt.exec(.{2});
    try stmt.exec(.{3});
}

test "encoding decoding null" {
    var conn = try Connection.init(std.testing.allocator, try std.Uri.parse("postgres://testing:testing@localhost:5432/testing"));
    defer conn.deinit();
    var stmt = try conn.prepare("SELECT $1, $2;");
    defer stmt.deinit();
    var a: ?u32 = null;
    var b: ?[]const u8 = "hi";
    var result = try stmt.query(struct { ?u8, ?[]const u8 }, .{ a, b });
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 1), result.data.len);
    try std.testing.expectEqual(@as(?u8, null), result.data[0].@"0");
    try std.testing.expectEqualStrings("hi", result.data[0].@"1".?);
}

test "get last error" {
    var conn = try Connection.init(std.testing.allocator, try std.Uri.parse("postgres://testing:testing@localhost:5432/testing"));
    defer conn.deinit();
    conn.exec("SELECT 1/0;") catch {
        try std.testing.expectEqual(Error.Severity.ERROR, conn.getLastError().getSeverity());
        try std.testing.expectEqualStrings("division by zero", conn.getLastError().getMessage());
    };
}
