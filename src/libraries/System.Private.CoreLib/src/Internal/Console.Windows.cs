// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Runtime.CompilerServices;
using System.Text;

namespace Internal
{
    public static partial class Console
    {
        [MethodImplAttribute(MethodImplOptions.NoInlining)]
        public static void Write(string s)
        {
            WriteCore(Interop.Kernel32.GetStdHandle(Interop.Kernel32.HandleTypes.STD_OUTPUT_HANDLE), s);
        }

        public static partial class Error
        {
            [MethodImplAttribute(MethodImplOptions.NoInlining)]
            public static void Write(string s)
            {
                WriteCore(Interop.Kernel32.GetStdHandle(Interop.Kernel32.HandleTypes.STD_ERROR_HANDLE), s);
            }
        }

        private static unsafe void WriteCore(IntPtr handle, string s)
        {
            int bufferSize = checked(s.Length * 4);
            Span<byte> bytes = (uint)bufferSize < 1024 ? stackalloc byte[bufferSize] : new byte[bufferSize];
            int cbytes;

            fixed (char* pChars = s)
            fixed (byte* pBytes = bytes)
            {
                cbytes = Interop.Kernel32.WideCharToMultiByte(
                    Interop.Kernel32.GetConsoleOutputCP(),
                    0, pChars, s.Length, pBytes, bytes.Length, null, null);
            }

            fixed (byte* pBytes = bytes)
            {
                Interop.Kernel32.WriteFile(handle, pBytes, cbytes, out _, IntPtr.Zero);
            }
        }
    }
}
