pub const Database = struct {
    pool: []Connection,
    pub fn init() void {}
    pub fn deinit() void {}
    pub fn exec() void {}
    pub fn query() void {}
    pub fn prepare() Statement {}
};

pub const Connection = struct {
    pub fn init() void {}
    pub fn deinit() void {}
    pub fn exec() void {}
    pub fn query() void {}
    pub fn prepare() Statement {}
};

pub const Statement = struct {
    pub fn exec() void {}
    pub fn query() void {}
    pub fn deinit() void {}
};