const std = @import("std");
const mbedtls = @cImport({
    @cInclude("mbedtls/ctr_drbg.h");
    @cInclude("mbedtls/debug.h");
    @cInclude("mbedtls/entropy.h");
    @cInclude("mbedtls/ssl.h");
});

pub const Stream = struct {
    allocator: std.mem.Allocator,
    stream: std.net.Stream,
    ssl: mbedtls.mbedtls_ssl_context,
    conf: mbedtls.mbedtls_ssl_config,
    ctr_drbg: mbedtls.mbedtls_ctr_drbg_context,
    entropy: mbedtls.mbedtls_entropy_context,
    cert: mbedtls.mbedtls_x509_crt,

    pub const ReadError = std.os.ReadError || error{SSLReadError};
    pub const WriteError = std.os.WriteError || error{SSLWriteError};

    pub const Reader = std.io.Reader(*Stream, ReadError, read);
    pub const Writer = std.io.Writer(*Stream, WriteError, write);

    pub fn reader(self: *Stream) Reader {
        return .{ .context = self };
    }

    pub fn writer(self: *Stream) Writer {
        return .{ .context = self };
    }

    pub fn init(allocator: std.mem.Allocator) !*Stream {
        var stream = try allocator.create(Stream);
        stream.allocator = allocator;
        return stream;
    }

    pub fn wrap(self: *Stream, stream: std.net.Stream) !void {
        self.stream = stream;

        mbedtls.mbedtls_ssl_init(&self.ssl);
        errdefer mbedtls.mbedtls_ssl_free(&self.ssl);

        mbedtls.mbedtls_ssl_config_init(&self.conf);
        errdefer mbedtls.mbedtls_ssl_config_free(&self.conf);

        mbedtls.mbedtls_ctr_drbg_init(&self.ctr_drbg);
        errdefer mbedtls.mbedtls_ctr_drbg_free(&self.ctr_drbg);

        mbedtls.mbedtls_entropy_init(&self.entropy);
        errdefer mbedtls.mbedtls_entropy_free(&self.entropy);

        mbedtls.mbedtls_x509_crt_init(&self.cert);
        errdefer mbedtls.mbedtls_x509_crt_free(&self.cert);

        var err = mbedtls.mbedtls_ctr_drbg_seed(&self.ctr_drbg, mbedtls.mbedtls_entropy_func, &self.entropy, null, 0);
        if (err != 0) {
            return error.SeedFailed;
        }

        err = mbedtls.mbedtls_ssl_config_defaults(&self.conf, mbedtls.MBEDTLS_SSL_IS_CLIENT, mbedtls.MBEDTLS_SSL_TRANSPORT_STREAM, mbedtls.MBEDTLS_SSL_PRESET_DEFAULT);
        if (err != 0) {
            return error.ConfigurationFailed;
        }
        mbedtls.mbedtls_ssl_conf_rng(&self.conf, mbedtls.mbedtls_ctr_drbg_random, &self.ctr_drbg);

        mbedtls.mbedtls_ssl_conf_authmode(&self.conf, mbedtls.MBEDTLS_SSL_VERIFY_NONE);

        err = mbedtls.mbedtls_ssl_setup(&self.ssl, &self.conf);
        if (err != 0) {
            return error.SetupFailed;
        }

        mbedtls.mbedtls_ssl_set_bio(&self.ssl, self, write_callback, read_callback, null);
    }

    pub fn set_hostname(self: *Stream, maybeHost: ?[]const u8) !void {
        var err: c_int = undefined;

        if (maybeHost) |host| {
            var hostname = try std.cstr.addNullByte(self.allocator, host);
            defer self.allocator.free(hostname);
            err = mbedtls.mbedtls_ssl_set_hostname(&self.ssl, hostname.ptr);
        } else {
            err = mbedtls.mbedtls_ssl_set_hostname(&self.ssl, null);
        }
        if (err != 0) {
            return error.HostnameSetFailed;
        }
    }

    pub fn handshake(self: *Stream) !void {
        var err = mbedtls.mbedtls_ssl_handshake(&self.ssl);
        if (err != 0) {
            return error.HandshakeFailed;
        }
    }

    pub fn deinit(self: *Stream) void {
        _ = mbedtls.mbedtls_ssl_close_notify(&self.ssl);
        mbedtls.mbedtls_ssl_free(&self.ssl);
        mbedtls.mbedtls_ssl_config_free(&self.conf);
        mbedtls.mbedtls_ctr_drbg_free(&self.ctr_drbg);
        mbedtls.mbedtls_entropy_free(&self.entropy);
        mbedtls.mbedtls_x509_crt_free(&self.cert);
        self.allocator.destroy(self);
    }

    fn read_callback(ptr: ?*anyopaque, buf: [*c]u8, len: usize) callconv(.C) c_int {
        var self = @intToPtr(*Stream, @ptrToInt(ptr));
        var ret = self.stream.read(buf[0..len]) catch return -1;
        return @intCast(c_int, ret);
    }

    fn write_callback(ptr: ?*anyopaque, buf: [*c]const u8, len: usize) callconv(.C) c_int {
        var self = @intToPtr(*Stream, @ptrToInt(ptr));
        var ret = self.stream.write(buf[0..len]) catch return -1;
        return @intCast(c_int, ret);
    }

    pub fn read(self: *Stream, buffer: []u8) ReadError!usize {
        var ret = mbedtls.mbedtls_ssl_read(&self.ssl, buffer.ptr, buffer.len);
        if (ret < 0 and ret != mbedtls.MBEDTLS_ERR_SSL_WANT_READ and ret != mbedtls.MBEDTLS_ERR_SSL_WANT_WRITE and ret != mbedtls.MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS and ret != mbedtls.MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS) {
            return ReadError.SSLReadError;
        }
        return @intCast(usize, ret);
    }

    pub fn write(self: *Stream, buffer: []const u8) WriteError!usize {
        var ret = mbedtls.mbedtls_ssl_write(&self.ssl, buffer.ptr, buffer.len);
        if (ret < 0 and ret != mbedtls.MBEDTLS_ERR_SSL_WANT_READ and ret != mbedtls.MBEDTLS_ERR_SSL_WANT_WRITE and ret != mbedtls.MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS and ret != mbedtls.MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS) {
            return WriteError.SSLWriteError;
        }
        return @intCast(usize, ret);
    }
};
