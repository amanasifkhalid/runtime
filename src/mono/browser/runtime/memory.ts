// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

import WasmEnableThreads from "consts:wasmEnableThreads";

import { MemOffset, NumberOrPointer } from "./types/internal";
import { VoidPtr, CharPtr } from "./types/emscripten";
import cwraps, { I52Error } from "./cwraps";
import { loaderHelpers, Module, mono_assert, runtimeHelpers } from "./globals";
import { utf8ToString } from "./strings";
import { mono_log_warn, mono_log_error } from "./logging";

const alloca_stack: Array<VoidPtr> = [];
const alloca_buffer_size = 32 * 1024;
let alloca_base: VoidPtr, alloca_offset: VoidPtr, alloca_limit: VoidPtr;

function _ensure_allocated (): void {
    if (alloca_base)
        return;
    alloca_base = malloc(alloca_buffer_size);
    alloca_offset = alloca_base;
    alloca_limit = <VoidPtr>(<any>alloca_base + alloca_buffer_size);
}

const max_int64_big = BigInt("9223372036854775807");
const min_int64_big = BigInt("-9223372036854775808");

export function temp_malloc (size: number): VoidPtr {
    _ensure_allocated();
    if (!alloca_stack.length)
        throw new Error("No temp frames have been created at this point");

    const result = alloca_offset;
    alloca_offset += <any>size;
    if (alloca_offset >= alloca_limit)
        throw new Error("Out of temp storage space");
    return result;
}

// returns always uint32 (not negative Number)
export function malloc (size: number): VoidPtr {
    return (Module._malloc(size) as any >>> 0) as any;
}

export function free (ptr: VoidPtr) {
    Module._free(ptr);
}

export function _create_temp_frame (): void {
    _ensure_allocated();
    alloca_stack.push(alloca_offset);
}

export function _release_temp_frame (): void {
    if (!alloca_stack.length)
        throw new Error("No temp frames have been created at this point");

    alloca_offset = <VoidPtr>alloca_stack.pop();
}


function assert_int_in_range (value: Number, min: Number, max: Number) {
    mono_check(Number.isSafeInteger(value), () => `Value is not an integer: ${value} (${typeof (value)})`);
    mono_check(value >= min && value <= max, () => `Overflow: value ${value} is out of ${min} ${max} range`);
}

export function _zero_region (byteOffset: VoidPtr, sizeBytes: number): void {
    localHeapViewU8().fill(0, <any>byteOffset, <any>byteOffset + sizeBytes);
}

/** note: MonoBoolean is 8 bits not 32 bits when inside a structure or array */
export function setB32 (offset: MemOffset, value: number | boolean): void {
    receiveWorkerHeapViews();
    const boolValue = !!value;
    if (typeof (value) === "number")
        assert_int_in_range(value, 0, 1);
    Module.HEAP32[<any>offset >>> 2] = boolValue ? 1 : 0;
}

export function setB8 (offset: MemOffset, value: number | boolean): void {
    const boolValue = !!value;
    if (typeof (value) === "number")
        assert_int_in_range(value, 0, 1);
    receiveWorkerHeapViews();
    Module.HEAPU8[<any>offset] = boolValue ? 1 : 0;
}

export function setU8 (offset: MemOffset, value: number): void {
    assert_int_in_range(value, 0, 0xFF);
    receiveWorkerHeapViews();
    Module.HEAPU8[<any>offset] = value;
}

export function setU16 (offset: MemOffset, value: number): void {
    assert_int_in_range(value, 0, 0xFFFF);
    receiveWorkerHeapViews();
    Module.HEAPU16[<any>offset >>> 1] = value;
}

// does not check for growable heap
export function setU16_local (localView: Uint16Array, offset: MemOffset, value: number): void {
    assert_int_in_range(value, 0, 0xFFFF);
    localView[<any>offset >>> 1] = value;
}

// does not check for overflow nor growable heap
export function setU16_unchecked (offset: MemOffset, value: number): void {
    Module.HEAPU16[<any>offset >>> 1] = value;
}

// does not check for overflow nor growable heap
export function setU32_unchecked (offset: MemOffset, value: NumberOrPointer): void {
    Module.HEAPU32[<any>offset >>> 2] = <number><any>value;
}

export function setU32 (offset: MemOffset, value: NumberOrPointer): void {
    assert_int_in_range(<any>value, 0, 0xFFFF_FFFF);
    receiveWorkerHeapViews();
    Module.HEAPU32[<any>offset >>> 2] = <number><any>value;
}

export function setI8 (offset: MemOffset, value: number): void {
    assert_int_in_range(value, -0x80, 0x7F);
    receiveWorkerHeapViews();
    Module.HEAP8[<any>offset] = value;
}

export function setI16 (offset: MemOffset, value: number): void {
    assert_int_in_range(value, -0x8000, 0x7FFF);
    receiveWorkerHeapViews();
    Module.HEAP16[<any>offset >>> 1] = value;
}

export function setI32_unchecked (offset: MemOffset, value: number): void {
    receiveWorkerHeapViews();
    Module.HEAP32[<any>offset >>> 2] = value;
}

export function setI32 (offset: MemOffset, value: number): void {
    assert_int_in_range(<any>value, -0x8000_0000, 0x7FFF_FFFF);
    receiveWorkerHeapViews();
    Module.HEAP32[<any>offset >>> 2] = value;
}

function autoThrowI52 (error: I52Error) {
    if (error === I52Error.NONE)
        return;

    switch (error) {
        case I52Error.NON_INTEGRAL:
            throw new Error("value was not an integer");
        case I52Error.OUT_OF_RANGE:
            throw new Error("value out of range");
        default:
            throw new Error("unknown internal error");
    }
}

/**
 * Throws for values which are not 52 bit integer. See Number.isSafeInteger()
 */
export function setI52 (offset: MemOffset, value: number): void {
    mono_check(Number.isSafeInteger(value), () => `Value is not a safe integer: ${value} (${typeof (value)})`);
    receiveWorkerHeapViews();
    const error = cwraps.mono_wasm_f64_to_i52(<any>offset, value);
    autoThrowI52(error);
}

/**
 * Throws for values which are not 52 bit integer or are negative. See Number.isSafeInteger().
 */
export function setU52 (offset: MemOffset, value: number): void {
    mono_check(Number.isSafeInteger(value), () => `Value is not a safe integer: ${value} (${typeof (value)})`);
    mono_check(value >= 0, "Can't convert negative Number into UInt64");
    receiveWorkerHeapViews();
    const error = cwraps.mono_wasm_f64_to_u52(<any>offset, value);
    autoThrowI52(error);
}

export function setI64Big (offset: MemOffset, value: bigint): void {
    mono_check(typeof value === "bigint", () => `Value is not an bigint: ${value} (${typeof (value)})`);
    mono_check(value >= min_int64_big && value <= max_int64_big, () => `Overflow: value ${value} is out of ${min_int64_big} ${max_int64_big} range`);

    Module.HEAP64[<any>offset >>> 3] = value;
}

export function setF32 (offset: MemOffset, value: number): void {
    mono_check(typeof value === "number", () => `Value is not a Number: ${value} (${typeof (value)})`);
    receiveWorkerHeapViews();
    Module.HEAPF32[<any>offset >>> 2] = value;
}

export function setF64 (offset: MemOffset, value: number): void {
    mono_check(typeof value === "number", () => `Value is not a Number: ${value} (${typeof (value)})`);
    receiveWorkerHeapViews();
    Module.HEAPF64[<any>offset >>> 3] = value;
}

let warnDirtyBool = true;

export function getB32 (offset: MemOffset): boolean {
    receiveWorkerHeapViews();
    const value = (Module.HEAPU32[<any>offset >>> 2]);
    if (value > 1 && warnDirtyBool) {
        warnDirtyBool = false;
        mono_log_warn(`getB32: value at ${offset} is not a boolean, but a number: ${value}`);
    }
    return !!value;
}

export function getB8 (offset: MemOffset): boolean {
    receiveWorkerHeapViews();
    return !!(Module.HEAPU8[<any>offset]);
}

export function getU8 (offset: MemOffset): number {
    receiveWorkerHeapViews();
    return Module.HEAPU8[<any>offset];
}

export function getU16 (offset: MemOffset): number {
    receiveWorkerHeapViews();
    return Module.HEAPU16[<any>offset >>> 1];
}

// does not check for growable heap
export function getU16_local (localView: Uint16Array, offset: MemOffset): number {
    return localView[<any>offset >>> 1];
}

export function getU32 (offset: MemOffset): number {
    receiveWorkerHeapViews();
    return Module.HEAPU32[<any>offset >>> 2];
}

// does not check for growable heap
export function getU32_local (localView: Uint32Array, offset: MemOffset): number {
    return localView[<any>offset >>> 2];
}

export function getI32_unaligned (offset: MemOffset): number {
    return cwraps.mono_wasm_get_i32_unaligned(<any>offset);
}

export function getU32_unaligned (offset: MemOffset): number {
    return cwraps.mono_wasm_get_i32_unaligned(<any>offset) >>> 0;
}

export function getF32_unaligned (offset: MemOffset): number {
    return cwraps.mono_wasm_get_f32_unaligned(<any>offset);
}

export function getF64_unaligned (offset: MemOffset): number {
    return cwraps.mono_wasm_get_f64_unaligned(<any>offset);
}

export function getI8 (offset: MemOffset): number {
    receiveWorkerHeapViews();
    return Module.HEAP8[<any>offset];
}

export function getI16 (offset: MemOffset): number {
    receiveWorkerHeapViews();
    return Module.HEAP16[<any>offset >>> 1];
}

// does not check for growable heap
export function getI16_local (localView: Int16Array, offset: MemOffset): number {
    return localView[<any>offset >>> 1];
}

export function getI32 (offset: MemOffset): number {
    receiveWorkerHeapViews();
    return Module.HEAP32[<any>offset >>> 2];
}

// does not check for growable heap
export function getI32_local (localView: Int32Array, offset: MemOffset): number {
    return localView[<any>offset >>> 2];
}

/**
 * Throws for Number.MIN_SAFE_INTEGER > value > Number.MAX_SAFE_INTEGER
 */
export function getI52 (offset: MemOffset): number {
    const result = cwraps.mono_wasm_i52_to_f64(<any>offset, runtimeHelpers._i52_error_scratch_buffer);
    const error = getI32(runtimeHelpers._i52_error_scratch_buffer);
    autoThrowI52(error);
    return result;
}

/**
 * Throws for 0 > value > Number.MAX_SAFE_INTEGER
 */
export function getU52 (offset: MemOffset): number {
    const result = cwraps.mono_wasm_u52_to_f64(<any>offset, runtimeHelpers._i52_error_scratch_buffer);
    const error = getI32(runtimeHelpers._i52_error_scratch_buffer);
    autoThrowI52(error);
    return result;
}

export function getI64Big (offset: MemOffset): bigint {
    receiveWorkerHeapViews();
    return Module.HEAP64[<any>offset >>> 3];
}

export function getF32 (offset: MemOffset): number {
    receiveWorkerHeapViews();
    return Module.HEAPF32[<any>offset >>> 2];
}

export function getF64 (offset: MemOffset): number {
    receiveWorkerHeapViews();
    return Module.HEAPF64[<any>offset >>> 3];
}

/// Allocates a new buffer of the given size on the Emscripten stack and passes a pointer to it to the callback.
/// Returns the result of the callback.  As usual with stack allocations, the buffer is freed when the callback returns.
/// Do not attempt to use the stack pointer after the callback is finished.
export function withStackAlloc<TResult>(bytesWanted: number, f: (ptr: VoidPtr) => TResult): TResult;
export function withStackAlloc<T1, TResult>(bytesWanted: number, f: (ptr: VoidPtr, ud1: T1) => TResult, ud1: T1): TResult;
export function withStackAlloc<T1, T2, TResult>(bytesWanted: number, f: (ptr: VoidPtr, ud1: T1, ud2: T2) => TResult, ud1: T1, ud2: T2): TResult;
export function withStackAlloc<T1, T2, T3, TResult>(bytesWanted: number, f: (ptr: VoidPtr, ud1: T1, ud2: T2, ud3: T3) => TResult, ud1: T1, ud2: T2, ud3: T3): TResult;
export function withStackAlloc<T1, T2, T3, TResult> (bytesWanted: number, f: (ptr: VoidPtr, ud1?: T1, ud2?: T2, ud3?: T3) => TResult, ud1?: T1, ud2?: T2, ud3?: T3): TResult {
    const sp = Module.stackSave();
    const ptr = Module.stackAlloc(bytesWanted);
    try {
        return f(ptr, ud1, ud2, ud3);
    } finally {
        if (loaderHelpers.is_runtime_running()) Module.stackRestore(sp);

    }
}

// @bytes must be a typed array. space is allocated for it in the native heap
//  and it is copied to that location. returns the address of the allocation.
export function mono_wasm_load_bytes_into_heap (bytes: Uint8Array): VoidPtr {
    // pad sizes by 16 bytes for simd
    const memoryOffset = malloc(bytes.length + 16);
    if (<any>memoryOffset <= 0) {
        mono_log_error(`malloc failed to allocate ${(bytes.length + 16)} bytes.`);
        throw new Error("Out of memory");
    }
    const heapBytes = new Uint8Array(localHeapViewU8().buffer, <any>memoryOffset, bytes.length);
    heapBytes.set(bytes);
    return memoryOffset;
}

// @bytes must be a typed array. space is allocated for it in memory
//  and it is copied to that location. returns the address of the data.
// the result pointer *cannot* be freed because malloc is bypassed for speed.
export function mono_wasm_load_bytes_into_heap_persistent (bytes: Uint8Array): VoidPtr {
    // pad sizes by 16 bytes for simd
    const desiredSize = bytes.length + 16;
    // sbrk doesn't allocate whole pages so we can ask it for as many bytes as we want.
    let memoryOffset = Module._sbrk(desiredSize);
    if (<any>memoryOffset <= 0) {
        // sbrk failed. Due to identical bugs in v8 and spidermonkey, this isn't guaranteed to be OOM.
        // We use this function early during startup, when OOM shouldn't be possible anyway!
        // Log a warning, then retry.
        memoryOffset = Module._sbrk(desiredSize);
        if (<any>memoryOffset <= 0) {
            mono_log_error(`sbrk failed to allocate ${desiredSize} bytes, and failed upon retry.`);
            throw new Error("Out of memory");
        } else {
            mono_log_warn(`sbrk failed to allocate ${desiredSize} bytes, but succeeded upon retry!`);
        }
    }
    const heapBytes = new Uint8Array(localHeapViewU8().buffer, <any>memoryOffset, bytes.length);
    heapBytes.set(bytes);
    return memoryOffset;
}

export function getEnv (name: string): string | null {
    let charPtr: CharPtr = <any>0;
    try {
        charPtr = cwraps.mono_wasm_getenv(name);
        if (<any>charPtr === 0)
            return null;
        else return utf8ToString(charPtr);
    } finally {
        if (charPtr) Module._free(<any>charPtr);
    }
}

export function compareExchangeI32 (offset: MemOffset, value: number, expected: number): number {
    mono_assert((<any>offset & 3) === 0, () => `compareExchangeI32: offset must be 4-byte aligned, got ${offset}`);
    if (!WasmEnableThreads) {
        const actual = getI32(offset);
        if (actual === expected) {
            setI32(offset, value);
        }
        return actual;
    }
    return globalThis.Atomics.compareExchange(localHeapViewI32(), <any>offset >>> 2, expected, value);
}

export function storeI32 (offset: MemOffset, value: number): void {
    mono_assert((<any>offset & 3) === 0, () => `storeI32: offset must be 4-byte aligned, got ${offset}`);
    if (!WasmEnableThreads) return setI32(offset, value);
    globalThis.Atomics.store(localHeapViewI32(), <any>offset >>> 2, value);
}

export function notifyI32 (offset: MemOffset, count: number): void {
    mono_assert((<any>offset & 3) === 0, () => `notifyI32: offset must be 4-byte aligned, got ${offset}`);
    if (!WasmEnableThreads) return;
    globalThis.Atomics.notify(localHeapViewI32(), <any>offset >>> 2, count);
}

// returns memory view which is valid within current synchronous call stack
export function localHeapViewI8 (): Int8Array {
    receiveWorkerHeapViews();
    return Module.HEAP8;
}

// returns memory view which is valid within current synchronous call stack
export function localHeapViewI16 (): Int16Array {
    receiveWorkerHeapViews();
    return Module.HEAP16;
}

// returns memory view which is valid within current synchronous call stack
export function localHeapViewI32 (): Int32Array {
    receiveWorkerHeapViews();
    return Module.HEAP32;
}

// returns memory view which is valid within current synchronous call stack
export function localHeapViewI64Big (): BigInt64Array {
    receiveWorkerHeapViews();
    return Module.HEAP64;
}

// returns memory view which is valid within current synchronous call stack
export function localHeapViewU8 (): Uint8Array {
    receiveWorkerHeapViews();
    return Module.HEAPU8;
}

// returns memory view which is valid within current synchronous call stack
export function localHeapViewU16 (): Uint16Array {
    receiveWorkerHeapViews();
    return Module.HEAPU16;
}

// returns memory view which is valid within current synchronous call stack
export function localHeapViewU32 (): Uint32Array {
    receiveWorkerHeapViews();
    return Module.HEAPU32;
}

// returns memory view which is valid within current synchronous call stack
export function localHeapViewF32 (): Float32Array {
    receiveWorkerHeapViews();
    return Module.HEAPF32;
}

// returns memory view which is valid within current synchronous call stack
export function localHeapViewF64 (): Float64Array {
    receiveWorkerHeapViews();
    return Module.HEAPF64;
}

export function copyBytes (srcPtr: VoidPtr, dstPtr: VoidPtr, bytes: number): void {
    const heap = localHeapViewU8();
    heap.copyWithin(dstPtr as any, srcPtr as any, srcPtr as any + bytes);
}

// when we run with multithreading enabled, we need to make sure that the memory views are updated on each worker
// on non-MT build, this will be a no-op trimmed by rollup
export function receiveWorkerHeapViews () {
    if (!WasmEnableThreads) return;
    const wasmMemory = runtimeHelpers.getMemory();
    if (wasmMemory.buffer !== Module.HEAPU8.buffer) {
        runtimeHelpers.updateMemoryViews();
    }
}

const sharedArrayBufferDefined = typeof SharedArrayBuffer !== "undefined";
export function isSharedArrayBuffer (buffer: any): buffer is SharedArrayBuffer {
    // this condition should be eliminated by rollup on non-threading builds
    if (!WasmEnableThreads) return false;
    // BEWARE: In some cases, `instanceof SharedArrayBuffer` returns false even though buffer is an SAB.
    // Patch adapted from https://github.com/emscripten-core/emscripten/pull/16994
    // See also https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Symbol/toStringTag
    return sharedArrayBufferDefined && buffer[Symbol.toStringTag] === "SharedArrayBuffer";
}

/*
Problem: When WebWorker is suspended in the browser, the other running threads could `grow` the linear memory in the meantime.
After the thread is un-suspended C code may to try to de-reference pointer which is beyond it's known view.
This is likely V8 bug. We don't have direct evidence, just failed debugger unit tests with MT runtime.
*/
export function forceThreadMemoryViewRefresh () {
    // this condition should be eliminated by rollup on non-threading builds and it would become empty method.
    if (!WasmEnableThreads) return;

    const wasmMemory = runtimeHelpers.getMemory();

    /*
    Normally when wasm memory grows in v8, this size change is broadcast to other web workers via an 'interrupt', which works by setting a thread-local flag that needs to be checked.
    It's possible that at this point in execution the flag has not been checked yet (because this worker was suspended by the debugger in an unknown location),
    which means the size change has not taken effect in this worker.
    wasmMemory.grow's implementation in v8 checks to see whether other workers have already grown the buffer,
    and will update the current worker's knowledge of the buffer's size.
    After that we should be able to safely updateMemoryViews and get a correctly sized view.
    This only works because their implementation does not skip doing work even when you ask to grow by 0 pages.
    */
    wasmMemory.grow(0);
    if (wasmMemory.buffer !== Module.HEAPU8.buffer) {
        runtimeHelpers.updateMemoryViews();
    }
}

export function fixupPointer (signature: any, shiftAmount: number): any {
    return ((signature as any) >>> shiftAmount) as any;
}
