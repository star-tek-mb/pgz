// TODO: do not hardcode array sizes
// TODO: tidy this code

const std = @import("std");
const messaging = @import("messaging.zig");
const WriteBuffer = messaging.WriteBuffer;
const Md5 = std.crypto.hash.Md5;
const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
const Base64 = std.base64.standard;

pub fn md5(user: []const u8, password: []const u8, salt: []const u8) [35]u8 {
    var digest: [16]u8 = undefined;
    var hasher = Md5.init(.{});
    hasher.update(password);
    hasher.update(user);
    hasher.final(&digest);
    hasher = Md5.init(.{});
    hasher.update(&hexDigest(digest));
    hasher.update(salt);
    hasher.final(&digest);
    return ("md5" ++ hexDigest(digest)).*;
}

const hex_charset = "0123456789abcdef";
fn hexDigest(digest: [16]u8) [32]u8 {
    var ret: [32]u8 = undefined;
    for (digest) |byte, i| {
        ret[i * 2 + 0] = hex_charset[byte >> 4];
        ret[i * 2 + 1] = hex_charset[byte & 15];
    }
    return ret;
}

pub const Scram = struct {
    buffer: [512]u8 = undefined,
    state: State,

    pub const State = union(enum) {
        update: struct {
            nonce: [24]u8,
            password: []const u8,
        },
        finish: struct {
            salted_password: [32]u8,
            auth: []const u8,
            message: []const u8,
        },
        done: void,

        pub fn writeTo(self: *State, wb: *WriteBuffer) void {
            switch (self.*) {
                .update => |u| {
                    var len = "n,,n=,r=".len + u.nonce.len;
                    wb.writeString("SCRAM-SHA-256");
                    wb.writeInt(u32, @intCast(u32, len));
                    wb.writeBytes("n,,n=,r=");
                    wb.writeBytes(&u.nonce);
                },
                .finish => |f| {
                    wb.writeBytes(f.message);
                },
                .done => {},
            }
        }
    };

    pub fn init(password: []const u8) Scram {
        var nonce: [24]u8 = undefined;
        var randomizer = std.rand.Xoshiro256.init(@intCast(u64, std.time.milliTimestamp()));
        for (nonce) |*b| {
            var byte = randomizer.random().intRangeAtMost(u8, 0x21, 0x7e);
            if (byte == 0x2c) {
                byte = 0x7e;
            }
            b.* = byte;
        }

        return Scram{
            .state = .{
                .update = .{
                    .nonce = nonce,
                    .password = password,
                },
            },
        };
    }

    pub fn update(self: *Scram, message: []const u8) !void {
        if (std.meta.activeTag(self.state) != .update) return error.InvalidState;

        var nonce: []const u8 = "";
        var salt: []const u8 = "";
        var iterations: []const u8 = "";

        var parser = std.mem.tokenize(u8, message, ",");
        while (parser.next()) |kv| {
            if (kv[0] == 'r' and kv.len > 2) {
                nonce = kv[2..];
            }
            if (kv[0] == 's' and kv.len > 2) {
                salt = kv[2..];
            }
            if (kv[0] == 'i' and kv.len > 2) {
                iterations = kv[2..];
            }
        }
        if (nonce.len == 0 or salt.len == 0 or iterations.len == 0) {
            return error.InvalidInput;
        }

        if (!std.mem.startsWith(u8, nonce, &self.state.update.nonce)) {
            return error.InvalidInput;
        }

        var decoded_salt_buf: [32]u8 = undefined;
        var decoded_salt_len = try Base64.Decoder.calcSizeForSlice(salt);
        if (decoded_salt_len > 32) return error.OutOfMemory;
        try Base64.Decoder.decode(&decoded_salt_buf, salt);
        var decoded_salt = decoded_salt_buf[0..decoded_salt_len];

        var salted_password = hi(self.state.update.password, decoded_salt, try std.fmt.parseInt(usize, iterations, 10));
        var hmac = Hmac.init(&salted_password);
        hmac.update("Client Key");
        var client_key: [Hmac.key_length]u8 = undefined;
        hmac.final(&client_key);

        var sha256 = std.crypto.hash.sha2.Sha256.init(.{});
        sha256.update(&client_key);
        var stored_key = sha256.finalResult();

        // base64 of 'n,,'
        const cbind = "biws";

        var finish_state = Scram.State{ .finish = undefined };

        finish_state.finish.auth = try std.fmt.bufPrint(self.buffer[0..256], "n=,r={s},{s},c={s},r={s}", .{
            self.state.update.nonce,
            message,
            cbind,
            nonce,
        });

        var client_hmac = Hmac.init(&stored_key);
        client_hmac.update(finish_state.finish.auth);
        var client_signature: [Hmac.key_length]u8 = undefined;
        client_hmac.final(&client_signature);

        var client_proof = client_key;
        var i: usize = 0;
        while (i < Hmac.key_length) : (i += 1) {
            client_proof[i] ^= client_signature[i];
        }

        var encoded_proof: [Base64.Encoder.calcSize(Hmac.key_length)]u8 = undefined;
        _ = Base64.Encoder.encode(&encoded_proof, &client_proof);

        finish_state.finish.message = try std.fmt.bufPrint(self.buffer[256..512], "c={s},r={s},p={s}", .{
            cbind,
            nonce,
            &encoded_proof,
        });

        finish_state.finish.salted_password = salted_password;
        self.state = finish_state;
    }

    pub fn finish(self: *Scram, message: []const u8) !void {
        if (std.meta.activeTag(self.state) != .finish) return error.InvalidState;
        if (message[0] != 'v' and message.len <= 2) return error.InvalidInput;

        var verifier = message[2..];
        var verifier_buf: [128]u8 = undefined;
        var verifier_len = try Base64.Decoder.calcSizeForSlice(verifier);
        if (verifier_len > 128) return error.OutOfMemory;
        try Base64.Decoder.decode(&verifier_buf, verifier);
        var decoded_verified = verifier_buf[0..verifier_len];

        var hmac = Hmac.init(&self.state.finish.salted_password);
        hmac.update("Server Key");
        var server_key: [32]u8 = undefined;
        hmac.final(&server_key);

        hmac = Hmac.init(&server_key);
        hmac.update(self.state.finish.auth);
        var hashed_verified: [Hmac.key_length]u8 = undefined;
        hmac.final(&hashed_verified);

        if (!std.mem.eql(u8, decoded_verified, &hashed_verified)) return error.VerifyError;

        self.state = .{ .done = {} };
    }
};

fn hi(string: []const u8, salt: []const u8, iterations: usize) [32]u8 {
    var result: [Hmac.key_length]u8 = undefined;

    var hmac = Hmac.init(string);
    hmac.update(salt);
    hmac.update(&.{ 0, 0, 0, 1 });
    var previous: [Hmac.key_length]u8 = undefined;
    hmac.final(&previous);

    result = previous;

    var i: usize = 1;
    while (i < iterations) : (i += 1) {
        var hmac_iter = Hmac.init(string);
        hmac_iter.update(&previous);
        hmac_iter.final(&previous);

        var j: usize = 0;
        while (j < Hmac.key_length) : (j += 1) {
            result[j] ^= previous[j];
        }
    }

    return result;
}

test "scram-sha-256" {
    const password = "foobar";
    const nonce = "9IZ2O01zb9IgiIZ1WJ/zgpJB";
    const client_first = "n,,n=,r=9IZ2O01zb9IgiIZ1WJ/zgpJB";
    const server_first = "r=9IZ2O01zb9IgiIZ1WJ/zgpJBjx/oIRLs02gGSHcw1KEty3eY,s=fs3IXBy7U7+IvVjZ,i=4096";
    const client_final = "c=biws,r=9IZ2O01zb9IgiIZ1WJ/zgpJBjx/oIRLs02gGSHcw1KEty3eY,p=AmNKosjJzS31NTlQYNs5BTeQjdHdk7lOflDo5re2an8=";
    const server_final = "v=U+ppxD5XUKtradnv8e2MkeupiA8FU87Sg8CXzXHDAzw=";

    var wb = try WriteBuffer.init(std.testing.allocator, 'p');
    defer wb.deinit();

    var scram = Scram.init(password);
    std.mem.copy(u8, scram.state.update.nonce[0..], nonce[0..]);
    scram.state.writeTo(&wb);
    try std.testing.expectEqualStrings(client_first, wb.buf.items[23..]);

    try scram.update(server_first);
    wb.reset('p');
    scram.state.writeTo(&wb);
    try std.testing.expectEqualStrings(client_final, wb.buf.items[5..]);

    try scram.finish(server_final);
}
