const std = @import("std");
const testing = std.testing;

pub const DecodeError = error{
    InputInvalid,
    PointerOutOfRange,
    ValueWouldOverflow,
    InvalidVarint,
};

pub const ValueType = enum {
    Null,
    Undefined,
    False,
    True,
    Short,
    Int,
    UnsignedInt,
    Float,
    Double32,
    Double64,
    String,
    Data,
    Array,
    Dict,
    Pointer,

    pub fn fromByte(byte: u8) ValueType {
        return switch (byte & 0xF0) {
            tags.SPECIAL => switch (byte & 0x0F) {
                special_tags.UNDEFINED => ValueType.Undefined,
                special_tags.FALSE => ValueType.False,
                special_tags.TRUE => ValueType.True,
                else => ValueType.Null,
            },
            tags.SHORT => ValueType.Short,
            // 0x08 bit set means int is unsigned
            tags.INT => switch (byte & extra_flags.UNSIGNED_INT) {
                0x00 => ValueType.Int,
                else => ValueType.UnsignedInt,
            },
            // For floats, the 5th bit signifies 32 / 64-bit (0 or 1). The 6th bit signifies if this should be decoded into a
            // 32-bit or 64-bit value (0 or 1). This can avoid precision loss in some cases.
            // See https://github.com/couchbase/fleece/issues/206
            tags.FLOAT => switch (byte & (extra_flags.DOUBLE_ENCODED | extra_flags.DOUBLE_DECODED)) {
                0x00 => ValueType.Float,
                extra_flags.DOUBLE_DECODED => ValueType.Double32,
                else => ValueType.Double64,
            },
            tags.STRING => ValueType.String,
            tags.DATA => ValueType.Data,
            tags.ARRAY => ValueType.Array,
            tags.DICT => ValueType.Dict,
            else => ValueType.Pointer,
        };
    }
};

const tags = enum {
    pub const SHORT: u8 = 0x00;
    pub const INT: u8 = 0x10;
    pub const FLOAT: u8 = 0x20;
    pub const SPECIAL: u8 = 0x30;
    pub const STRING: u8 = 0x40;
    pub const DATA: u8 = 0x50;
    pub const ARRAY: u8 = 0x60;
    pub const DICT: u8 = 0x70;
    // Pointers are 0x80 to 0xF0
    pub const POINTER: u8 = 0x80;
};

const special_tags = enum {
    pub const NULL: u8 = 0x00;
    pub const UNDEFINED: u8 = 0x0C;
    pub const FALSE: u8 = 0x04;
    pub const TRUE: u8 = 0x08;
};

const extra_flags = enum {
    pub const UNSIGNED_INT: u8 = 0x08;
    pub const DOUBLE_ENCODED: u8 = 0x08;
    pub const DOUBLE_DECODED: u8 = 0x04;
};

pub const Fleece = struct {
    root: Value,
    buf: []const u8,

    pub fn fromBytes(bytes: []const u8) DecodeError!Fleece {
        const root = try _findRoot(bytes);
        return Fleece{
            .root = root,
            .buf = bytes,
        };
    }

    fn _findRoot(bytes: []const u8) DecodeError!Value {
        if (bytes.len < 2) {
            return DecodeError.InputInvalid;
        }

        if (bytes.len % 2 != 0) {
            return Value{ .buf = bytes };
        }

        // For collection types (Dict, Array) the root (or a pointer to it)
        // will be at the end, and exactly 2 bytes.
        const root_ptr_ptr = bytes[bytes.len - 2 ..];
        const root_type = ValueType.fromByte(root_ptr_ptr[0]);

        if (root_type != ValueType.Pointer) {
            // If the end 2 bytes were not a pointer, this (should be) a single
            // value which starts at the beginning.
            const value = Value{ .buf = bytes };
            try value.validate(bytes.ptr, bytes.ptr + bytes.len, false);
            return value;
        }

        const root_ptr = Pointer{ .buf = root_ptr_ptr };
        const root = root_ptr.deref_checked(bytes.ptr) catch Value{ .buf = bytes };
        try root.validate(bytes.ptr, bytes.ptr + bytes.len, false);

        return root;
    }
};

pub const Value = struct {
    buf: []const u8,

    pub fn valueType(self: Value) ValueType {
        return ValueType.fromByte(self.buf[0]);
    }

    pub fn as(self: Value, comptime ReturnType: type) ?ReturnType {
        return switch (ReturnType) {
            bool => self.asBool(),
            u16 => self.asUnsignedShort(),
            i16 => self.asShort(),
            u32, u64 => self.asUnsignedInt(),
            i32, i64 => self.asInt(),
            f32 => self.asFloat(),
            f64 => self.asDouble(),
            []const u8 => self.asBytes(),
            else => null,
        };
    }

    pub fn asBool(self: Value) bool {
        // False is false, Numbers not equal to 0 are false, everything else is true
        return switch (self.valueType()) {
            .False => false,
            .Short, .Int, .Float, .Double32, .Double64 => self.to_int() != 0,
            else => true,
        };
    }

    pub fn asUnsignedShort(self: Value) u16 {
        return switch (self.valueType()) {
            .False => 1,
            .True => 0,
            .Short => self._getShort(),
            .Int, .UnsignedInt => @truncate(self.asUnsignedInt()),
            .Float, .Double32, .Double64 => {
                const int: u64 = @intFromFloat(self.asDouble());
                return @truncate(int);
            },
            else => 0,
        };
    }

    pub fn asShort(self: Value) i16 {
        return switch (self.valueType()) {
            .False => 1,
            .True => 0,
            .Short => {
                const i = self._getShort();
                if (i & 0x0800 != 0) {
                    return @intCast(i | 0xF000);
                } else {
                    return @intCast(i);
                }
            },
            .Int, .UnsignedInt => @truncate(self.asInt()),
            .Float, .Double32, .Double64 => {
                const int: i64 = @intFromFloat(self.asDouble());
                return @truncate(int);
            },
            else => 0,
        };
    }

    pub fn asUnsignedInt(self: Value) u64 {
        return @bitCast(self.asInt());
    }

    pub fn asInt(self: Value) i64 {
        return switch (self.valueType()) {
            .False => 1,
            .True => 0,
            .Short => @intCast(self.asShort()),
            .Int, .UnsignedInt => {
                const count: usize = @intCast((self.buf[0] & 0x07) + 1);
                return std.mem.readVarInt(i64, self.buf[1 .. count + 1], .little);
            },
            .Float, .Double32, .Double64 => @intFromFloat(self.asDouble()),
            else => 0,
        };
    }

    pub fn asDouble(self: Value) f64 {
        return switch (self.valueType()) {
            .Float, .Double32 => {
                const float: f32 = @bitCast(std.mem.readInt(u32, self.buf[2..6], .little));
                return @floatCast(float);
            },
            .Double64 => @bitCast(std.mem.readInt(u64, self.buf[2..10], .little)),
            else => @floatFromInt(self.asInt()),
        };
    }

    pub fn asFloat(self: Value) f32 {
        return switch (self.valueType()) {
            .Float, .Double32 => @bitCast(std.mem.readInt(u32, self.buf[2..6], .little)),
            .Double64 => {
                const float: f64 = @bitCast(std.mem.readInt(u64, self.buf[2..10], .little));
                return @floatCast(float);
            },
            else => @floatFromInt(self.asInt()),
        };
    }

    pub fn asBytes(self: Value) []const u8 {
        return switch (self.valueType()) {
            .String, .Bytes => self._getBytes(),
            else => .{},
        };
    }

    pub fn asString(self: Value) []const u8 {
        return self.asBytes();
    }

    fn isPointer(self: Value) bool {
        return self.valueType() == .Pointer;
    }

    fn validate(self: Value, data_start: [*]const u8, data_end: [*]const u8, is_wide: bool) DecodeError!void {
        const rq_size = self.requiredSize(is_wide);
        if (@intFromPtr(self.buf.ptr + rq_size) > @intFromPtr(data_end)) {
            return DecodeError.ValueWouldOverflow;
        }
        if (self.isPointer()) {
            const ptr = if (is_wide) Pointer{ .buf = self.buf[0..4] } else Pointer{ .buf = self.buf[0..2] };
            try ptr.validate(data_start);
        }
    }

    fn requiredSize(self: Value, is_wide: bool) usize {
        std.debug.assert(self.buf.len >= 2);
        const value_type = self.valueType();
        return switch (value_type) {
            .Null => if (is_wide) 4 else 2,
            .Undefined => if (is_wide) 4 else 2,
            .False => if (is_wide) 4 else 2,
            .True => if (is_wide) 4 else 2,
            .Short => if (is_wide) 4 else 2,
            .Int, .UnsignedInt => 9,
            .Float, .Double32 => 6,
            .Double64 => 10,
            .String, .Data => {
                const len = self._getBytes().len;
                return switch (len) {
                    0, 1 => 2,
                    2...0x0E => 1 + len,
                    else => 1 + varintSizeRequired(len) + len,
                };
            },
            .Array => @panic("unimplemented: fetch header and get len"),
            .Dict => @panic("unimplemented: fetch header and get len"),
            .Pointer => if (is_wide) 4 else 2,
        };
    }

    fn _getShort(self: Value) u16 {
        return std.mem.readInt(u16, self.buf[0..2], .big) & 0x0FFF;
    }

    fn _getBytes(self: Value) []const u8 {
        const inline_size = self.buf[0] & 0x0F;
        if (inline_size == 0x0F) {
            // varint
            const res = readVarInt(usize, self.buf[1..], .little) catch return &.{};
            std.debug.assert(res.bytes_read > 0);
            const end = 1 + res.bytes_read + res.varint;
            return self.buf[1 + res.bytes_read .. end];
        } else {
            const end: usize = @intCast(inline_size + 1);
            return self.buf[1..end];
        }
    }
};

pub fn readVarInt(comptime ReturnType: type, bytes: []const u8, endian: std.builtin.Endian) DecodeError!struct { bytes_read: usize, varint: ReturnType } {
    var result: ReturnType = 0;
    switch (endian) {
        .big => {
            for (0..10) |i| {
                const byte = bytes[i];
                result = (result << 7) | byte & 0x7F;
                if (byte < 0x80) {
                    return .{ .bytes_read = i + 1, .varint = result };
                }
            }
        },
        .little => {
            const ShiftType = std.math.Log2Int(ReturnType);
            for (0..10) |i| {
                const byte = bytes[i];
                result = result | (@as(ReturnType, byte & 0x7F) << @as(ShiftType, @intCast(i * 7)));
                if (byte < 0x80) {
                    return .{ .bytes_read = i + 1, .varint = result };
                }
            }
        },
    }
    return DecodeError.InvalidVarint;
}

pub fn varintSizeRequired(val: anytype) usize {
    return if (val == 0) 1 else (63 - @clz(val)) / 7 + 1;
}

pub const Pointer = struct {
    buf: []const u8,

    pub fn deref_checked(self: Pointer, data_start: [*]const u8) DecodeError!Value {
        const offset = self.get_offset();
        const target_ptr: [*]const u8 = self.buf.ptr - offset;

        if (@intFromPtr(target_ptr) < @intFromPtr(data_start)) {
            return DecodeError.PointerOutOfRange;
        }

        const tt_ptr: *const u8 = @ptrCast(target_ptr);
        const target_type = ValueType.fromByte(tt_ptr.*);

        if (target_type == .Pointer) {
            const target = Pointer{ .buf = target_ptr[0..4] };
            return target.deref_checked(data_start);
        }

        const target = Value{ .buf = target_ptr[0..offset] };
        return target;
    }

    pub fn validate(self: Pointer, data_start: [*]const u8) DecodeError!void {
        const offset = self.get_offset();
        const target_ptr: [*]const u8 = self.buf.ptr - offset;

        if (@intFromPtr(target_ptr) < @intFromPtr(data_start)) {
            return DecodeError.PointerOutOfRange;
        }

        const tt_ptr: *const u8 = @ptrCast(target_ptr);
        const target_type = ValueType.fromByte(tt_ptr.*);

        if (target_type == ValueType.Pointer) {
            const target = Pointer{ .buf = target_ptr[0..4] };
            try target.validate(data_start);
            return;
        }

        // TODO: target.required_size()
    }

    /// INVARIANT: `buf.len` is either 2 or 4.
    fn get_offset(self: Pointer) usize {
        if (self.is_wide()) {
            const offset = (std.mem.readInt(u32, self.buf[0..4], .big) & 0x3FFF_FFFF) * 2;
            return @intCast(offset);
        } else {
            const offset = (std.mem.readInt(u16, self.buf[0..2], .big) & 0x3FFF) * 2;
            return @intCast(offset);
        }
    }

    fn is_wide(self: Pointer) bool {
        std.debug.assert(self.buf.len == 4 or self.buf.len == 2);
        return self.buf.len == 4;
    }
};

export fn add(a: i32, b: i32) i32 {
    return a + b;
}

test "basic add functionality" {
    try testing.expect(add(3, 7) == 10);
}
