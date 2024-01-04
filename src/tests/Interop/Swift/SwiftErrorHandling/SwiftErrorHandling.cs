// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.Swift;
using System.Text;
using Xunit;

public class ErrorHandlingTests
{
    private const string SwiftLib = "libSwiftErrorHandling.dylib";

    [UnmanagedCallConv(CallConvs = new Type[] { typeof(CallConvSwift) })]
    [DllImport(SwiftLib, EntryPoint = "$s18SwiftErrorHandling018conditionallyThrowB004willE0SiSb_tKF")]
    public unsafe static extern nint conditionallyThrowError(bool willThrow, SwiftError* error);

    [Fact]
    public unsafe static void TestSwiftErrorThrown()
    {
        SwiftError error;

        // This will throw an error
        conditionallyThrowError(true, &error);
	Console.WriteLine($"After: {error.Value}");
        Assert.True(error.Value != IntPtr.Zero, "A Swift error was expected to be thrown.");
    }

    [Fact]
    public unsafe static void TestSwiftErrorNotThrown()
    {
        SwiftError error;

        // This will not throw an error
        int result = (int)conditionallyThrowError(false, &error);
	Console.WriteLine($"After: {error.Value}");

        Assert.True(error.Value == IntPtr.Zero, "No Swift error was expected to be thrown.");
        Assert.True(result == 42, "The result from Swift does not match the expected value.");
    }
}