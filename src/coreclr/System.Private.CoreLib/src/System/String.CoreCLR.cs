// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;
using System.Text;

namespace System
{
    public partial class String
    {
        [LibraryImport(RuntimeHelpers.QCall, EntryPoint = "String_StrCns")]
        private static unsafe partial string* StrCnsInternal(uint rid, IntPtr scopeHandle);

        // implementation of CORINFO_HELP_STRCNS
        [StackTraceHidden]
        [DebuggerStepThrough]
        [DebuggerHidden]
        internal static unsafe string StrCns(uint rid, IntPtr scopeHandle)
        {
            string* ptr = StrCnsInternal(rid, scopeHandle);
            Debug.Assert(ptr != null);
            return *ptr;
        }

        [MethodImpl(MethodImplOptions.InternalCall)]
        internal static extern unsafe string FastAllocateString(MethodTable *pMT, int length);

        [DebuggerHidden]
        internal static unsafe string FastAllocateString(int length)
        {
            return FastAllocateString(TypeHandle.TypeHandleOf<string>().AsMethodTable(), length);
        }

        [LibraryImport(RuntimeHelpers.QCall, EntryPoint = "String_Intern")]
        private static partial void Intern(StringHandleOnStack src);

        public static string Intern(string str)
        {
            ArgumentNullException.ThrowIfNull(str);
            Intern(new StringHandleOnStack(ref str!));
            return str!;
        }

        [LibraryImport(RuntimeHelpers.QCall, EntryPoint = "String_IsInterned")]
        private static partial void IsInterned(StringHandleOnStack src);

        public static string? IsInterned(string str)
        {
            ArgumentNullException.ThrowIfNull(str);
            IsInterned(new StringHandleOnStack(ref str!));
            return str;
        }

        // Copies the source String (byte buffer) to the destination IntPtr memory allocated with len bytes.
        // Used by ilmarshalers.cpp
        internal static unsafe void InternalCopy(string src, IntPtr dest, int len)
        {
            if (len != 0)
            {
                SpanHelpers.Memmove(ref *(byte*)dest, ref src.GetRawStringDataAsUInt8(), (nuint)len);
            }
        }

        internal unsafe int GetBytesFromEncoding(byte* pbNativeBuffer, int cbNativeBuffer, Encoding encoding)
        {
            // encoding == Encoding.UTF8
            fixed (char* pwzChar = &_firstChar)
            {
                return encoding.GetBytes(pwzChar, Length, pbNativeBuffer, cbNativeBuffer);
            }
        }
    }
}
