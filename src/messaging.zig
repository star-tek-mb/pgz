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
    tag: ?u8 = null,
    buf: std.ArrayList(u8),
    index: u32 = 0,

    pub fn init(allocator: std.mem.Allocator, maybe_tag: ?u8) !WriteBuffer {
        var buf = try std.ArrayList(u8).initCapacity(allocator, 512);
        if (maybe_tag) |tag| {
            try buf.append(tag);
        }
        _ = try buf.addManyAsArray(4);
        return WriteBuffer{ .buf = buf, .tag = maybe_tag };
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

    pub fn finalize(self: *WriteBuffer) void {
        if (self.tag == null) {
            std.mem.writeIntBig(u32, self.buf.items[self.index..][0..4], @intCast(u32, self.buf.items.len - self.index));
        } else {
            std.mem.writeIntBig(u32, self.buf.items[self.index + 1 ..][0..4], @intCast(u32, self.buf.items.len - self.index - 1));
        }
    }

    pub fn reset(self: *WriteBuffer, maybe_tag: ?u8) void {
        self.buf.clearRetainingCapacity();
        self.tag = maybe_tag;
        if (maybe_tag) |tag| {
            self.buf.append(tag) catch {};
        }
        _ = self.buf.addManyAsArray(4) catch {};
        self.index = 0;
    }

    pub fn next(self: *WriteBuffer, maybe_tag: ?u8) void {
        self.finalize();
        self.index = @intCast(u32, self.buf.items.len);
        self.tag = maybe_tag;
        if (maybe_tag) |tag| {
            self.buf.append(tag) catch {};
        }
        _ = self.buf.addManyAsArray(4) catch {};
    }

    /// finalizes buffer before sending
    pub fn send(self: *WriteBuffer, stream: std.net.Stream) !void {
        self.finalize();
        try stream.writeAll(self.buf.items);
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
        if (len > 4) {
            var msg = try allocator.alloc(u8, len - 4);
            _ = try reader.read(msg);
            return Message{ .type = @"type", .len = len, .msg = msg };
        }
        return Message{ .type = @"type", .len = len, .msg = &.{} };
    }

    pub fn free(self: *Message, allocator: std.mem.Allocator) void {
        allocator.free(self.msg);
    }
};

test "read buffer" {
    const data = [_]u8{ 0, 0, 0, 5, 0, 0, 0, 12, 72, 101, 108, 108, 111, 0, 119, 111, 114, 108, 100, 0 };
    var buf = ReadBuffer.init(&data);
    try std.testing.expectEqual(@as(u32, 5), buf.readInt(u32));
    try std.testing.expectEqual(@as(u32, 12), buf.readInt(u32));
    try std.testing.expectEqualStrings("Hello", buf.readString());
    try std.testing.expectEqualStrings("world", buf.readString());
}

test "write buffer" {
    const data = [_]u8{ 0, 0, 0, 24, 0, 0, 0, 5, 0, 0, 0, 12, 72, 101, 108, 108, 111, 0, 119, 111, 114, 108, 100, 0 };
    var buf = try WriteBuffer.init(std.testing.allocator, null);
    defer buf.deinit();
    buf.writeInt(u32, 5);
    buf.writeInt(u32, 12);
    buf.writeString("Hello");
    buf.writeString("world");
    buf.finalize();
    try std.testing.expectEqualSlices(u8, data[0..], buf.buf.items[0..]);
}
