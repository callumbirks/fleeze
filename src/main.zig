const std = @import("std");
const fleece = @import("root.zig");

test "short" {
    // A fleece-encoded short with the value 1461.
    const bytes: [2]u8 = .{ 0x05, 0xB5 };
    var runtime_zero: usize = 0;
    _ = &runtime_zero;
    const val = try fleece.Fleece.fromBytes(bytes[runtime_zero..]);
    const short = val.root.asShort();
    try std.testing.expectEqual(1461, short);
    const as_short = val.root.as(u16);
    try std.testing.expectEqual(1461, as_short);
}

test "int" {
    // A fleece-encoded int with the value 19_548_461.
    const bytes: [5]u8 = .{ 0x13, 0x2D, 0x49, 0x2A, 0x01 };
    var runtime_zero: usize = 0;
    _ = &runtime_zero;
    const val = try fleece.Fleece.fromBytes(bytes[runtime_zero..]);
    var int: ?i64 = val.root.asInt();
    try std.testing.expectEqual(19548461, int);
    int = val.root.as(i64);
    try std.testing.expectEqual(19548461, int);
    var uint: ?u64 = val.root.asUnsignedInt();
    try std.testing.expectEqual(19548461, uint);
    uint = val.root.as(u64);
    try std.testing.expectEqual(19548461, uint);
}
