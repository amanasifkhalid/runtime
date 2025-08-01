// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.ExceptionServices;
using System.Runtime.Versioning;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace System.IO
{
    // Class for creating FileStream objects, and some basic file management
    // routines such as Delete, etc.
    public static partial class File
    {
        private const int ChunkSize = 8192;

        // UTF-8 without BOM and with error detection. Same as the default encoding for StreamWriter.
        private static Encoding UTF8NoBOM => field ??= new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

        internal const int DefaultBufferSize = 4096;

        public static StreamReader OpenText(string path)
            => new StreamReader(path);

        public static StreamWriter CreateText(string path)
            => new StreamWriter(path, append: false);

        public static StreamWriter AppendText(string path)
            => new StreamWriter(path, append: true);

        /// <summary>
        /// Copies an existing file to a new file.
        /// An exception is raised if the destination file already exists.
        /// </summary>
        public static void Copy(string sourceFileName, string destFileName)
            => Copy(sourceFileName, destFileName, overwrite: false);

        /// <summary>
        /// Copies an existing file to a new file.
        /// If <paramref name="overwrite"/> is false, an exception will be
        /// raised if the destination exists. Otherwise it will be overwritten.
        /// </summary>
        public static void Copy(string sourceFileName, string destFileName, bool overwrite)
        {
            ArgumentException.ThrowIfNullOrEmpty(sourceFileName);
            ArgumentException.ThrowIfNullOrEmpty(destFileName);

            FileSystem.CopyFile(Path.GetFullPath(sourceFileName), Path.GetFullPath(destFileName), overwrite);
        }

        // Creates a file in a particular path.  If the file exists, it is replaced.
        // The file is opened with ReadWrite access and cannot be opened by another
        // application until it has been closed.  An IOException is thrown if the
        // directory specified doesn't exist.
        public static FileStream Create(string path)
            => Create(path, DefaultBufferSize);

        // Creates a file in a particular path.  If the file exists, it is replaced.
        // The file is opened with ReadWrite access and cannot be opened by another
        // application until it has been closed.  An IOException is thrown if the
        // directory specified doesn't exist.
        public static FileStream Create(string path, int bufferSize)
            => new FileStream(path, FileMode.Create, FileAccess.ReadWrite, FileShare.None, bufferSize);

        public static FileStream Create(string path, int bufferSize, FileOptions options)
            => new FileStream(path, FileMode.Create, FileAccess.ReadWrite, FileShare.None, bufferSize, options);

        // Deletes a file. The file specified by the designated path is deleted.
        // If the file does not exist, Delete succeeds without throwing
        // an exception.
        //
        // On Windows, Delete will fail for a file that is open for normal I/O
        // or a file that is memory mapped.
        public static void Delete(string path)
        {
            ArgumentNullException.ThrowIfNull(path);
            FileSystem.DeleteFile(Path.GetFullPath(path));
        }

        // Tests whether a file exists. The result is true if the file
        // given by the specified path exists; otherwise, the result is
        // false.  Note that if path describes a directory,
        // Exists will return false.
        public static bool Exists([NotNullWhen(true)] string? path)
        {
            try
            {
                if (path == null)
                    return false;
                if (path.Length == 0)
                    return false;

                path = Path.GetFullPath(path);

                // After normalizing, check whether path ends in directory separator.
                // Otherwise, FillAttributeInfo removes it and we may return a false positive.
                // GetFullPath should never return null
                Debug.Assert(path != null, "File.Exists: GetFullPath returned null");
                if (path.Length > 0 && PathInternal.IsDirectorySeparator(path[^1]))
                {
                    return false;
                }

                return FileSystem.FileExists(path);
            }
            catch (ArgumentException) { }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }

            return false;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="FileStream" /> class with the specified path, creation mode, read/write and sharing permission, the access other FileStreams can have to the same file, the buffer size, additional file options and the allocation size.
        /// </summary>
        /// <remarks><see cref="FileStream(string,FileStreamOptions)"/> for information about exceptions.</remarks>
        public static FileStream Open(string path, FileStreamOptions options) => new FileStream(path, options);

        public static FileStream Open(string path, FileMode mode)
            => Open(path, mode, (mode == FileMode.Append ? FileAccess.Write : FileAccess.ReadWrite), FileShare.None);

        public static FileStream Open(string path, FileMode mode, FileAccess access)
            => Open(path, mode, access, FileShare.None);

        public static FileStream Open(string path, FileMode mode, FileAccess access, FileShare share)
            => new FileStream(path, mode, access, share);

        /// <summary>
        /// Initializes a new instance of the <see cref="SafeFileHandle" /> class with the specified path, creation mode, read/write and sharing permission, the access other SafeFileHandles can have to the same file, additional file options and the allocation size.
        /// </summary>
        /// <param name="path">A relative or absolute path for the file that the current <see cref="SafeFileHandle" /> instance will encapsulate.</param>
        /// <param name="mode">One of the enumeration values that determines how to open or create the file. The default value is <see cref="FileMode.Open" /></param>
        /// <param name="access">A bitwise combination of the enumeration values that determines how the file can be accessed. The default value is <see cref="FileAccess.Read" /></param>
        /// <param name="share">A bitwise combination of the enumeration values that determines how the file will be shared by processes. The default value is <see cref="FileShare.Read" />.</param>
        /// <param name="preallocationSize">The initial allocation size in bytes for the file. A positive value is effective only when a regular file is being created, overwritten, or replaced.
        /// Negative values are not allowed. In other cases (including the default 0 value), it's ignored.</param>
        /// <param name="options">An object that describes optional <see cref="SafeFileHandle" /> parameters to use.</param>
        /// <exception cref="T:System.ArgumentNullException"><paramref name="path" /> is <see langword="null" />.</exception>
        /// <exception cref="T:System.ArgumentException"><paramref name="path" /> is an empty string (""), contains only white space, or contains one or more invalid characters.
        /// -or-
        /// <paramref name="path" /> refers to a non-file device, such as <c>CON:</c>, <c>COM1:</c>, <c>LPT1:</c>, etc. in an NTFS environment.</exception>
        /// <exception cref="T:System.NotSupportedException"><paramref name="path" /> refers to a non-file device, such as <c>CON:</c>, <c>COM1:</c>, <c>LPT1:</c>, etc. in a non-NTFS environment.</exception>
        /// <exception cref="T:System.ArgumentOutOfRangeException"><paramref name="preallocationSize" /> is negative.
        /// -or-
        /// <paramref name="mode" />, <paramref name="access" />, or <paramref name="share" /> contain an invalid value.</exception>
        /// <exception cref="T:System.IO.FileNotFoundException">The file cannot be found, such as when <paramref name="mode" /> is <see cref="FileMode.Truncate" /> or <see cref="FileMode.Open" />, and the file specified by <paramref name="path" /> does not exist. The file must already exist in these modes.</exception>
        /// <exception cref="T:System.IO.IOException">An I/O error, such as specifying <see cref="FileMode.CreateNew" /> when the file specified by <paramref name="path" /> already exists, occurred.
        ///  -or-
        ///  The disk was full (when <paramref name="preallocationSize" /> was provided and <paramref name="path" /> was pointing to a regular file).
        ///  -or-
        ///  The file was too large (when <paramref name="preallocationSize" /> was provided and <paramref name="path" /> was pointing to a regular file).</exception>
        /// <exception cref="T:System.Security.SecurityException">The caller does not have the required permission.</exception>
        /// <exception cref="T:System.IO.DirectoryNotFoundException">The specified path is invalid, such as being on an unmapped drive.</exception>
        /// <exception cref="T:System.UnauthorizedAccessException">The <paramref name="access" /> requested is not permitted by the operating system for the specified <paramref name="path" />, such as when <paramref name="access" />  is <see cref="FileAccess.Write" /> or <see cref="FileAccess.ReadWrite" /> and the file or directory is set for read-only access.
        ///  -or-
        /// <see cref="F:System.IO.FileOptions.Encrypted" /> is specified for <paramref name="options" />, but file encryption is not supported on the current platform.</exception>
        /// <exception cref="T:System.IO.PathTooLongException">The specified path, file name, or both exceed the system-defined maximum length. </exception>
        public static SafeFileHandle OpenHandle(string path, FileMode mode = FileMode.Open, FileAccess access = FileAccess.Read,
            FileShare share = FileShare.Read, FileOptions options = FileOptions.None, long preallocationSize = 0)
        {
            Strategies.FileStreamHelpers.ValidateArguments(path, mode, access, share, bufferSize: 0, options, preallocationSize);

            return SafeFileHandle.Open(Path.GetFullPath(path), mode, access, share, options, preallocationSize);
        }

        // File and Directory UTC APIs treat a DateTimeKind.Unspecified as UTC whereas
        // ToUniversalTime treats this as local.
        internal static DateTimeOffset GetUtcDateTimeOffset(DateTime dateTime)
        {
            if (dateTime.Kind == DateTimeKind.Local)
                dateTime = dateTime.ToUniversalTime();

            return new DateTimeOffset(dateTime.Ticks, default);
        }

        public static void SetCreationTime(string path, DateTime creationTime)
            => FileSystem.SetCreationTime(Path.GetFullPath(path), creationTime, asDirectory: false);

        /// <summary>
        /// Sets the date and time the file or directory was created.
        /// </summary>
        /// <param name="fileHandle">
        /// A <see cref="SafeFileHandle" /> to the file or directory for which to set the creation date and time information.
        /// </param>
        /// <param name="creationTime">
        /// A <see cref="DateTime"/> containing the value to set for the creation date and time of <paramref name="fileHandle"/>.
        /// This value is expressed in local time.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="fileHandle"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// <paramref name="creationTime"/> specifies a value outside the range of dates, times, or both permitted for this operation.
        /// </exception>
        /// <exception cref="UnauthorizedAccessException">
        /// The caller does not have the required permission.
        /// </exception>
        /// <exception cref="IOException">
        /// An I/O error occurred while performing the operation.
        /// </exception>
        public static void SetCreationTime(SafeFileHandle fileHandle, DateTime creationTime)
        {
            ArgumentNullException.ThrowIfNull(fileHandle);
            FileSystem.SetCreationTime(fileHandle, creationTime);
        }

        public static void SetCreationTimeUtc(string path, DateTime creationTimeUtc)
            => FileSystem.SetCreationTime(Path.GetFullPath(path), GetUtcDateTimeOffset(creationTimeUtc), asDirectory: false);


        /// <summary>
        /// Sets the date and time, in coordinated universal time (UTC), that the file or directory was created.
        /// </summary>
        /// <param name="fileHandle">
        /// A <see cref="SafeFileHandle" /> to the file or directory for which to set the creation date and time information.
        /// </param>
        /// <param name="creationTimeUtc">
        /// A <see cref="DateTime"/> containing the value to set for the creation date and time of <paramref name="fileHandle"/>.
        /// This value is expressed in UTC time.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="fileHandle"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// <paramref name="creationTimeUtc"/> specifies a value outside the range of dates, times, or both permitted for this operation.
        /// </exception>
        /// <exception cref="UnauthorizedAccessException">
        /// The caller does not have the required permission.
        /// </exception>
        /// <exception cref="IOException">
        /// An I/O error occurred while performing the operation.
        /// </exception>
        public static void SetCreationTimeUtc(SafeFileHandle fileHandle, DateTime creationTimeUtc)
        {
            ArgumentNullException.ThrowIfNull(fileHandle);
            FileSystem.SetCreationTime(fileHandle, GetUtcDateTimeOffset(creationTimeUtc));
        }

        public static DateTime GetCreationTime(string path)
            => FileSystem.GetCreationTime(Path.GetFullPath(path)).LocalDateTime;

        /// <summary>
        /// Returns the creation date and time of the specified file or directory.
        /// </summary>
        /// <param name="fileHandle">
        /// A <see cref="SafeFileHandle" /> to the file or directory for which to obtain creation date and time information.
        /// </param>
        /// <returns>
        /// A <see cref="DateTime" /> structure set to the creation date and time for the specified file or
        /// directory. This value is expressed in local time.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="fileHandle"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="UnauthorizedAccessException">
        /// The caller does not have the required permission.
        /// </exception>
        public static DateTime GetCreationTime(SafeFileHandle fileHandle)
        {
            ArgumentNullException.ThrowIfNull(fileHandle);
            return FileSystem.GetCreationTime(fileHandle).LocalDateTime;
        }

        public static DateTime GetCreationTimeUtc(string path)
            => FileSystem.GetCreationTime(Path.GetFullPath(path)).UtcDateTime;

        /// <summary>
        /// Returns the creation date and time, in coordinated universal time (UTC), of the specified file or directory.
        /// </summary>
        /// <param name="fileHandle">
        /// A <see cref="SafeFileHandle" /> to the file or directory for which to obtain creation date and time information.
        /// </param>
        /// <returns>
        /// A <see cref="DateTime" /> structure set to the creation date and time for the specified file or
        /// directory. This value is expressed in UTC time.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="fileHandle"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="UnauthorizedAccessException">
        /// The caller does not have the required permission.
        /// </exception>
        public static DateTime GetCreationTimeUtc(SafeFileHandle fileHandle)
        {
            ArgumentNullException.ThrowIfNull(fileHandle);
            return FileSystem.GetCreationTime(fileHandle).UtcDateTime;
        }

        public static void SetLastAccessTime(string path, DateTime lastAccessTime)
            => FileSystem.SetLastAccessTime(Path.GetFullPath(path), lastAccessTime, false);

        /// <summary>
        /// Sets the date and time the specified file or directory was last accessed.
        /// </summary>
        /// <param name="fileHandle">
        /// A <see cref="SafeFileHandle" /> to the file or directory for which to set the last access date and time information.
        /// </param>
        /// <param name="lastAccessTime">
        /// A <see cref="DateTime"/> containing the value to set for the last access date and time of <paramref name="fileHandle"/>.
        /// This value is expressed in local time.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="fileHandle"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// <paramref name="lastAccessTime"/> specifies a value outside the range of dates, times, or both permitted for this operation.
        /// </exception>
        /// <exception cref="UnauthorizedAccessException">
        /// The caller does not have the required permission.
        /// </exception>
        /// <exception cref="IOException">
        /// An I/O error occurred while performing the operation.
        /// </exception>
        public static void SetLastAccessTime(SafeFileHandle fileHandle, DateTime lastAccessTime)
        {
            ArgumentNullException.ThrowIfNull(fileHandle);
            FileSystem.SetLastAccessTime(fileHandle, lastAccessTime);
        }

        public static void SetLastAccessTimeUtc(string path, DateTime lastAccessTimeUtc)
            => FileSystem.SetLastAccessTime(Path.GetFullPath(path), GetUtcDateTimeOffset(lastAccessTimeUtc), false);

        /// <summary>
        /// Sets the date and time, in coordinated universal time (UTC), that the specified file or directory was last accessed.
        /// </summary>
        /// <param name="fileHandle">
        /// A <see cref="SafeFileHandle" /> to the file or directory for which to set the last access date and time information.
        /// </param>
        /// <param name="lastAccessTimeUtc">
        /// A <see cref="DateTime"/> containing the value to set for the last access date and time of <paramref name="fileHandle"/>.
        /// This value is expressed in UTC time.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="fileHandle"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// <paramref name="lastAccessTimeUtc"/> specifies a value outside the range of dates, times, or both permitted for this operation.
        /// </exception>
        /// <exception cref="UnauthorizedAccessException">
        /// The caller does not have the required permission.
        /// </exception>
        /// <exception cref="IOException">
        /// An I/O error occurred while performing the operation.
        /// </exception>
        public static void SetLastAccessTimeUtc(SafeFileHandle fileHandle, DateTime lastAccessTimeUtc)
        {
            ArgumentNullException.ThrowIfNull(fileHandle);
            FileSystem.SetLastAccessTime(fileHandle, GetUtcDateTimeOffset(lastAccessTimeUtc));
        }

        public static DateTime GetLastAccessTime(string path)
            => FileSystem.GetLastAccessTime(Path.GetFullPath(path)).LocalDateTime;

        /// <summary>
        /// Returns the last access date and time of the specified file or directory.
        /// </summary>
        /// <param name="fileHandle">
        /// A <see cref="SafeFileHandle" /> to the file or directory for which to obtain last access date and time information.
        /// </param>
        /// <returns>
        /// A <see cref="DateTime" /> structure set to the last access date and time for the specified file or
        /// directory. This value is expressed in local time.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="fileHandle"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="UnauthorizedAccessException">
        /// The caller does not have the required permission.
        /// </exception>
        public static DateTime GetLastAccessTime(SafeFileHandle fileHandle)
        {
            ArgumentNullException.ThrowIfNull(fileHandle);
            return FileSystem.GetLastAccessTime(fileHandle).LocalDateTime;
        }

        public static DateTime GetLastAccessTimeUtc(string path)
            => FileSystem.GetLastAccessTime(Path.GetFullPath(path)).UtcDateTime;

        /// <summary>
        /// Returns the last access date and time, in coordinated universal time (UTC), of the specified file or directory.
        /// </summary>
        /// <param name="fileHandle">
        /// A <see cref="SafeFileHandle" /> to the file or directory for which to obtain last access date and time information.
        /// </param>
        /// <returns>
        /// A <see cref="DateTime" /> structure set to the last access date and time for the specified file or
        /// directory. This value is expressed in UTC time.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="fileHandle"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="UnauthorizedAccessException">
        /// The caller does not have the required permission.
        /// </exception>
        public static DateTime GetLastAccessTimeUtc(SafeFileHandle fileHandle)
        {
            ArgumentNullException.ThrowIfNull(fileHandle);
            return FileSystem.GetLastAccessTime(fileHandle).UtcDateTime;
        }

        public static void SetLastWriteTime(string path, DateTime lastWriteTime)
            => FileSystem.SetLastWriteTime(Path.GetFullPath(path), lastWriteTime, false);

        /// <summary>
        /// Sets the date and time that the specified file or directory was last written to.
        /// </summary>
        /// <param name="fileHandle">
        /// A <see cref="SafeFileHandle" /> to the file or directory for which to set the last write date and time information.
        /// </param>
        /// <param name="lastWriteTime">
        /// A <see cref="DateTime"/> containing the value to set for the last write date and time of <paramref name="fileHandle"/>.
        /// This value is expressed in local time.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="fileHandle"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// <paramref name="lastWriteTime"/> specifies a value outside the range of dates, times, or both permitted for this operation.
        /// </exception>
        /// <exception cref="UnauthorizedAccessException">
        /// The caller does not have the required permission.
        /// </exception>
        /// <exception cref="IOException">
        /// An I/O error occurred while performing the operation.
        /// </exception>
        public static void SetLastWriteTime(SafeFileHandle fileHandle, DateTime lastWriteTime)
        {
            ArgumentNullException.ThrowIfNull(fileHandle);
            FileSystem.SetLastWriteTime(fileHandle, lastWriteTime);
        }

        public static void SetLastWriteTimeUtc(string path, DateTime lastWriteTimeUtc)
            => FileSystem.SetLastWriteTime(Path.GetFullPath(path), GetUtcDateTimeOffset(lastWriteTimeUtc), false);

        /// <summary>
        /// Sets the date and time, in coordinated universal time (UTC), that the specified file or directory was last written to.
        /// </summary>
        /// <param name="fileHandle">
        /// A <see cref="SafeFileHandle" /> to the file or directory for which to set the last write date and time information.
        /// </param>
        /// <param name="lastWriteTimeUtc">
        /// A <see cref="DateTime"/> containing the value to set for the last write date and time of <paramref name="fileHandle"/>.
        /// This value is expressed in UTC time.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="fileHandle"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// <paramref name="lastWriteTimeUtc"/> specifies a value outside the range of dates, times, or both permitted for this operation.
        /// </exception>
        /// <exception cref="UnauthorizedAccessException">
        /// The caller does not have the required permission.
        /// </exception>
        /// <exception cref="IOException">
        /// An I/O error occurred while performing the operation.
        /// </exception>
        public static void SetLastWriteTimeUtc(SafeFileHandle fileHandle, DateTime lastWriteTimeUtc)
        {
            ArgumentNullException.ThrowIfNull(fileHandle);
            FileSystem.SetLastWriteTime(fileHandle, GetUtcDateTimeOffset(lastWriteTimeUtc));
        }

        public static DateTime GetLastWriteTime(string path)
            => FileSystem.GetLastWriteTime(Path.GetFullPath(path)).LocalDateTime;

        /// <summary>
        /// Returns the last write date and time of the specified file or directory.
        /// </summary>
        /// <param name="fileHandle">
        /// A <see cref="SafeFileHandle" /> to the file or directory for which to obtain last write date and time information.
        /// </param>
        /// <returns>
        /// A <see cref="DateTime" /> structure set to the last write date and time for the specified file or
        /// directory. This value is expressed in local time.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="fileHandle"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="UnauthorizedAccessException">
        /// The caller does not have the required permission.
        /// </exception>
        public static DateTime GetLastWriteTime(SafeFileHandle fileHandle)
        {
            ArgumentNullException.ThrowIfNull(fileHandle);
            return FileSystem.GetLastWriteTime(fileHandle).LocalDateTime;
        }

        public static DateTime GetLastWriteTimeUtc(string path)
            => FileSystem.GetLastWriteTime(Path.GetFullPath(path)).UtcDateTime;

        /// <summary>
        /// Returns the last write date and time, in coordinated universal time (UTC), of the specified file or directory.
        /// </summary>
        /// <param name="fileHandle">
        /// A <see cref="SafeFileHandle" /> to the file or directory for which to obtain last write date and time information.
        /// </param>
        /// <returns>
        /// A <see cref="DateTime" /> structure set to the last write date and time for the specified file or
        /// directory. This value is expressed in UTC time.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="fileHandle"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="UnauthorizedAccessException">
        /// The caller does not have the required permission.
        /// </exception>
        public static DateTime GetLastWriteTimeUtc(SafeFileHandle fileHandle)
        {
            ArgumentNullException.ThrowIfNull(fileHandle);
            return FileSystem.GetLastWriteTime(fileHandle).UtcDateTime;
        }

        public static FileAttributes GetAttributes(string path)
            => FileSystem.GetAttributes(Path.GetFullPath(path));

        /// <summary>
        /// Gets the specified <see cref="FileAttributes"/> of the file or directory associated to <paramref name="fileHandle"/>
        /// </summary>
        /// <param name="fileHandle">
        /// A <see cref="SafeFileHandle" /> to the file or directory for which the attributes are to be retrieved.
        /// </param>
        /// <returns>
        /// The <see cref="FileAttributes"/> of the file or directory.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="fileHandle"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="UnauthorizedAccessException">
        /// The caller does not have the required permission.
        /// </exception>
        public static FileAttributes GetAttributes(SafeFileHandle fileHandle)
        {
            ArgumentNullException.ThrowIfNull(fileHandle);
            return FileSystem.GetAttributes(fileHandle);
        }

        public static void SetAttributes(string path, FileAttributes fileAttributes)
            => FileSystem.SetAttributes(Path.GetFullPath(path), fileAttributes);

        /// <summary>
        /// Sets the specified <see cref="FileAttributes"/> of the file or directory associated to <paramref name="fileHandle"/>.
        /// </summary>
        /// <param name="fileHandle">
        /// A <see cref="SafeFileHandle" /> to the file or directory for which <paramref name="fileAttributes"/> should be set.
        /// </param>
        /// <param name="fileAttributes">
        /// A bitwise combination of the enumeration values.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="fileHandle"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="UnauthorizedAccessException">
        /// The caller does not have the required permission.
        /// </exception>
        /// <remarks>
        /// It is not possible to change the compression status of a <see cref="File"/> object
        /// using the <see cref="SetAttributes(SafeFileHandle, FileAttributes)"/> method.
        /// </remarks>
        public static void SetAttributes(SafeFileHandle fileHandle, FileAttributes fileAttributes)
        {
            ArgumentNullException.ThrowIfNull(fileHandle);
            FileSystem.SetAttributes(fileHandle, fileAttributes);
        }

        /// <summary>Gets the <see cref="T:System.IO.UnixFileMode" /> of the file on the path.</summary>
        /// <param name="path">The path to the file.</param>
        /// <returns>The <see cref="T:System.IO.UnixFileMode" /> of the file on the path.</returns>
        /// <exception cref="T:System.ArgumentException"><paramref name="path" /> is a zero-length string, or contains one or more invalid characters. You can query for invalid characters by using the <see cref="M:System.IO.Path.GetInvalidPathChars" /> method.</exception>
        /// <exception cref="T:System.ArgumentNullException"><paramref name="path" /> is <see langword="null" />.</exception>
        /// <exception cref="T:System.UnauthorizedAccessException">The caller does not have the required permission.</exception>
        /// <exception cref="T:System.IO.PathTooLongException">The specified path exceeds the system-defined maximum length.</exception>
        /// <exception cref="T:System.IO.DirectoryNotFoundException">A component of the <paramref name="path" /> is not a directory.</exception>
        /// <exception cref="T:System.IO.FileNotFoundException">The file cannot be found.</exception>
        [UnsupportedOSPlatform("windows")]
        public static UnixFileMode GetUnixFileMode(string path)
            => GetUnixFileModeCore(path);

        /// <summary>Gets the <see cref="T:System.IO.UnixFileMode" /> of the specified file handle.</summary>
        /// <param name="fileHandle">The file handle.</param>
        /// <returns>The <see cref="T:System.IO.UnixFileMode" /> of the file handle.</returns>
        /// <exception cref="T:System.ObjectDisposedException">The file is closed.</exception>
        [UnsupportedOSPlatform("windows")]
        public static UnixFileMode GetUnixFileMode(SafeFileHandle fileHandle)
            => GetUnixFileModeCore(fileHandle);

        /// <summary>Sets the specified <see cref="T:System.IO.UnixFileMode" /> of the file on the specified path.</summary>
        /// <param name="path">The path to the file.</param>
        /// <param name="mode">The unix file mode.</param>
        /// <exception cref="T:System.ArgumentException"><paramref name="path" /> is a zero-length string, or contains one or more invalid characters. You can query for invalid characters by using the <see cref="M:System.IO.Path.GetInvalidPathChars" /> method.</exception>
        /// <exception cref="T:System.ArgumentNullException"><paramref name="path" /> is <see langword="null" />.</exception>
        /// <exception cref="T:System.ArgumentException">The caller attempts to use an invalid file mode.</exception>
        /// <exception cref="T:System.UnauthorizedAccessException">The caller does not have the required permission.</exception>
        /// <exception cref="T:System.IO.PathTooLongException">The specified path exceeds the system-defined maximum length.</exception>
        /// <exception cref="T:System.IO.DirectoryNotFoundException">A component of the <paramref name="path" /> is not a directory.</exception>
        /// <exception cref="T:System.IO.FileNotFoundException">The file cannot be found.</exception>
        [UnsupportedOSPlatform("windows")]
        public static void SetUnixFileMode(string path, UnixFileMode mode)
            => SetUnixFileModeCore(path, mode);

        /// <summary>Sets the specified <see cref="T:System.IO.UnixFileMode" /> of the specified file handle.</summary>
        /// <param name="fileHandle">The file handle.</param>
        /// <param name="mode">The unix file mode.</param>
        /// <exception cref="T:System.ArgumentException">The caller attempts to use an invalid file mode.</exception>
        /// <exception cref="T:System.UnauthorizedAccessException">The caller does not have the required permission.</exception>
        /// <exception cref="T:System.ObjectDisposedException">The file is closed.</exception>
        [UnsupportedOSPlatform("windows")]
        public static void SetUnixFileMode(SafeFileHandle fileHandle, UnixFileMode mode)
            => SetUnixFileModeCore(fileHandle, mode);

        public static FileStream OpenRead(string path)
            => new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);

        public static FileStream OpenWrite(string path)
            => new FileStream(path, FileMode.OpenOrCreate, FileAccess.Write, FileShare.None);

        public static string ReadAllText(string path)
            => ReadAllText(path, Encoding.UTF8);

        public static string ReadAllText(string path, Encoding encoding)
        {
            Validate(path, encoding);

            using StreamReader sr = new StreamReader(path, encoding, detectEncodingFromByteOrderMarks: true);
            return sr.ReadToEnd();
        }

        public static void WriteAllText(string path, string? contents)
            => WriteAllText(path, contents, UTF8NoBOM);

        /// <summary>
        /// Creates a new file, writes the specified string to the file, and then closes the file.
        /// If the target file already exists, it is truncated and overwritten.
        /// </summary>
        /// <param name="path">The file to write to.</param>
        /// <param name="contents">The characters to write to the file.</param>
        /// <exception cref="ArgumentNullException"><paramref name="path"/> is <see langword="null"/>.</exception>
        /// <exception cref="ArgumentException"><paramref name="path"/> is empty.</exception>
        /// <exception cref="PathTooLongException">The specified path, file name, or both exceed the system-defined maximum length.</exception>
        /// <exception cref="DirectoryNotFoundException">The specified path is invalid (for example, it is on an unmapped drive).</exception>
        /// <exception cref="IOException">An I/O error occurred while opening the file.</exception>
        /// <exception cref="UnauthorizedAccessException"><paramref name="path"/> specified a file that is read-only.</exception>
        /// <exception cref="UnauthorizedAccessException"><paramref name="path"/> specified a file that is hidden.</exception>
        /// <exception cref="UnauthorizedAccessException"><paramref name="path"/> specified a directory.</exception>
        /// <exception cref="UnauthorizedAccessException">This operation is not supported on the current platform.</exception>
        /// <exception cref="UnauthorizedAccessException">The caller does not have the required permission.</exception>
        /// <exception cref="NotSupportedException"><paramref name="path"/> is in an invalid format.</exception>
        /// <remarks>
        /// This method uses UTF-8 encoding without a Byte-Order Mark (BOM), so using the GetPreamble method will return an empty byte array. If it is necessary to
        /// include a UTF-8 identifier, such as a byte order mark, at the beginning of a file, use the <see cref="WriteAllText(string, ReadOnlySpan{char}, Encoding)"/> method.
        /// </remarks>
        public static void WriteAllText(string path, ReadOnlySpan<char> contents)
            => WriteAllText(path, contents, UTF8NoBOM);

        public static void WriteAllText(string path, string? contents, Encoding encoding)
        {
            Validate(path, encoding);

            WriteToFile(path, FileMode.Create, contents, encoding);
        }

        /// <summary>
        /// Creates a new file, writes the specified string to the file using the specified encoding, and then closes the file.
        /// If the target file already exists, it is truncated and overwritten.
        /// </summary>
        /// <param name="path">The file to write to.</param>
        /// <param name="contents">The characters to write to the file.</param>
        /// <param name="encoding">The encoding to apply to the string.</param>
        /// <exception cref="ArgumentNullException"><paramref name="path"/> is <see langword="null"/>.</exception>
        /// <exception cref="ArgumentException"><paramref name="path"/> is empty.</exception>
        /// <exception cref="ArgumentNullException"><paramref name="encoding"/> is <see langword="null"/>.</exception>
        /// <exception cref="PathTooLongException">The specified path, file name, or both exceed the system-defined maximum length.</exception>
        /// <exception cref="DirectoryNotFoundException">The specified path is invalid (for example, it is on an unmapped drive).</exception>
        /// <exception cref="IOException">An I/O error occurred while opening the file.</exception>
        /// <exception cref="UnauthorizedAccessException"><paramref name="path"/> specified a file that is read-only.</exception>
        /// <exception cref="UnauthorizedAccessException"><paramref name="path"/> specified a file that is hidden.</exception>
        /// <exception cref="UnauthorizedAccessException"><paramref name="path"/> specified a directory.</exception>
        /// <exception cref="UnauthorizedAccessException">This operation is not supported on the current platform.</exception>
        /// <exception cref="UnauthorizedAccessException">The caller does not have the required permission.</exception>
        /// <exception cref="NotSupportedException"><paramref name="path"/> is in an invalid format.</exception>
        public static void WriteAllText(string path, ReadOnlySpan<char> contents, Encoding encoding)
        {
            Validate(path, encoding);

            WriteToFile(path, FileMode.Create, contents, encoding);
        }

        public static byte[] ReadAllBytes(string path)
        {
            // SequentialScan is a perf hint that requires extra sys-call on non-Windows OSes.
            FileOptions options = OperatingSystem.IsWindows() ? FileOptions.SequentialScan : FileOptions.None;
            using (SafeFileHandle sfh = OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.Read, options))
            {
                long fileLength = 0;
                if (sfh.CanSeek && (fileLength = sfh.GetFileLength()) > Array.MaxLength)
                {
                    throw new IOException(SR.IO_FileTooLong2GB);
                }

#if DEBUG
                fileLength = 0; // improve the test coverage for ReadAllBytesUnknownLength
#endif

                if (fileLength == 0)
                {
                    // Some file systems (e.g. procfs on Linux) return 0 for length even when there's content; also there are non-seekable files.
                    // Thus we need to assume 0 doesn't mean empty.
                    return ReadAllBytesUnknownLength(sfh);
                }

                int index = 0;
                int count = (int)fileLength;
                byte[] bytes = new byte[count];
                while (count > 0)
                {
                    int n = RandomAccess.ReadAtOffset(sfh, bytes.AsSpan(index, count), index);
                    if (n == 0)
                    {
                        ThrowHelper.ThrowEndOfFileException();
                    }

                    index += n;
                    count -= n;
                }
                return bytes;
            }
        }

        public static void WriteAllBytes(string path, byte[] bytes)
        {
            ArgumentNullException.ThrowIfNull(bytes);

            WriteAllBytes(path, new ReadOnlySpan<byte>(bytes));
        }

        /// <summary>
        /// Creates a new file, writes the specified byte array to the file, and then closes the file. If the target file already exists, it is truncated and overwritten.
        /// </summary>
        /// <param name="path">The file to write to.</param>
        /// <param name="bytes">The bytes to write to the file.</param>
        /// <exception cref="ArgumentNullException"><paramref name="path"/> is null.</exception>
        /// <exception cref="ArgumentException"><paramref name="path"/> is empty.</exception>
        /// <exception cref="PathTooLongException">The specified path, file name, or both exceed the system-defined maximum length.</exception>
        /// <exception cref="DirectoryNotFoundException">The specified path is invalid (for example, it is on an unmapped drive).</exception>
        /// <exception cref="IOException">An I/O error occurred while opening the file.</exception>
        /// <exception cref="UnauthorizedAccessException"><paramref name="path"/> specified a file that is read-only.</exception>
        /// <exception cref="UnauthorizedAccessException"><paramref name="path"/> specified a file that is hidden.</exception>
        /// <exception cref="UnauthorizedAccessException"><paramref name="path"/> specified a directory.</exception>
        /// <exception cref="UnauthorizedAccessException">The caller does not have the required permission.</exception>
        /// <exception cref="UnauthorizedAccessException">This operation is not supported on the current platform.</exception>
        /// <exception cref="NotSupportedException"><paramref name="path"/> is in an invalid format.</exception>
        public static void WriteAllBytes(string path, ReadOnlySpan<byte> bytes)
        {
            ArgumentException.ThrowIfNullOrEmpty(path);

            using SafeFileHandle sfh = OpenHandle(path, FileMode.Create, FileAccess.Write, FileShare.Read);
            RandomAccess.WriteAtOffset(sfh, bytes, 0);
        }

        /// <summary>
        /// Appends the specified byte array to the end of the file at the given path.
        /// If the file doesn't exist, this method creates a new file.
        /// </summary>
        /// <param name="path">The file to append to.</param>
        /// <param name="bytes">The bytes to append to the file.</param>
        /// <exception cref="ArgumentNullException"><paramref name="path"/> is null.</exception>
        /// <exception cref="ArgumentNullException"><paramref name="bytes"/> is null.</exception>
        /// <exception cref="ArgumentException"><paramref name="path"/> is empty.</exception>
        /// <exception cref="PathTooLongException">The specified path, file name, or both exceed the system-defined maximum length.</exception>
        /// <exception cref="DirectoryNotFoundException">The specified path is invalid (for example, it is on an unmapped drive).</exception>
        /// <exception cref="IOException">An I/O error occurred while opening the file.</exception>
        /// <exception cref="UnauthorizedAccessException"><paramref name="path"/> specified a file that is read-only.</exception>
        /// <exception cref="UnauthorizedAccessException"><paramref name="path"/> specified a file that is hidden.</exception>
        /// <exception cref="UnauthorizedAccessException"><paramref name="path"/> specified a directory.</exception>
        /// <exception cref="UnauthorizedAccessException">The caller does not have the required permission.</exception>
        /// <exception cref="UnauthorizedAccessException">This operation is not supported on the current platform.</exception>
        /// <exception cref="NotSupportedException"><paramref name="path"/> is in an invalid format.</exception>
        public static void AppendAllBytes(string path, byte[] bytes)
        {
            ArgumentNullException.ThrowIfNull(bytes);

            AppendAllBytes(path, new ReadOnlySpan<byte>(bytes));
        }

        /// <summary>
        /// Appends the specified byte array to the end of the file at the given path.
        /// If the file doesn't exist, this method creates a new file.
        /// </summary>
        /// <param name="path">The file to append to.</param>
        /// <param name="bytes">The bytes to append to the file.</param>
        /// <exception cref="ArgumentNullException"><paramref name="path"/> is null.</exception>
        /// <exception cref="ArgumentException"><paramref name="path"/> is empty.</exception>
        /// <exception cref="PathTooLongException">The specified path, file name, or both exceed the system-defined maximum length.</exception>
        /// <exception cref="DirectoryNotFoundException">The specified path is invalid (for example, it is on an unmapped drive).</exception>
        /// <exception cref="IOException">An I/O error occurred while opening the file.</exception>
        /// <exception cref="UnauthorizedAccessException"><paramref name="path"/> specified a file that is read-only.</exception>
        /// <exception cref="UnauthorizedAccessException"><paramref name="path"/> specified a file that is hidden.</exception>
        /// <exception cref="UnauthorizedAccessException"><paramref name="path"/> specified a directory.</exception>
        /// <exception cref="UnauthorizedAccessException">The caller does not have the required permission.</exception>
        /// <exception cref="UnauthorizedAccessException">This operation is not supported on the current platform.</exception>
        /// <exception cref="NotSupportedException"><paramref name="path"/> is in an invalid format.</exception>
        public static void AppendAllBytes(string path, ReadOnlySpan<byte> bytes)
        {
            ArgumentException.ThrowIfNullOrEmpty(path);

            using SafeFileHandle fileHandle = OpenHandle(path, FileMode.Append, FileAccess.Write, FileShare.Read);
            long fileOffset = RandomAccess.GetLength(fileHandle);
            RandomAccess.WriteAtOffset(fileHandle, bytes, fileOffset);
        }

        /// <summary>
        /// Asynchronously appends the specified byte array to the end of the file at the given path.
        /// If the file doesn't exist, this method creates a new file. If the operation is canceled, the task will return in a canceled state.
        /// </summary>
        /// <param name="path">The file to append to.</param>
        /// <param name="bytes">The bytes to append to the file.</param>
        /// <param name="cancellationToken">The token to monitor for cancellation requests. The default value is <see cref="CancellationToken.None"/>.</param>
        /// <returns>A task that represents the asynchronous append operation.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="path"/> is null.</exception>
        /// <exception cref="ArgumentNullException"><paramref name="bytes"/> is null.</exception>
        /// <exception cref="ArgumentException"><paramref name="path"/> is empty.</exception>
        /// <exception cref="OperationCanceledException">The cancellation token was canceled. This exception is stored into the returned task.</exception>
        public static Task AppendAllBytesAsync(string path, byte[] bytes, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(bytes);

            return AppendAllBytesAsync(path, new ReadOnlyMemory<byte>(bytes), cancellationToken);
        }

        /// <summary>
        /// Asynchronously appends the specified byte array to the end of the file at the given path.
        /// If the file doesn't exist, this method creates a new file. If the operation is canceled, the task will return in a canceled state.
        /// </summary>
        /// <param name="path">The file to append to.</param>
        /// <param name="bytes">The bytes to append to the file.</param>
        /// <param name="cancellationToken">The token to monitor for cancellation requests. The default value is <see cref="CancellationToken.None"/>.</param>
        /// <returns>A task that represents the asynchronous append operation.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="path"/> is null.</exception>
        /// <exception cref="ArgumentException"><paramref name="path"/> is empty.</exception>
        /// <exception cref="OperationCanceledException">The cancellation token was canceled. This exception is stored into the returned task.</exception>
        public static Task AppendAllBytesAsync(string path, ReadOnlyMemory<byte> bytes, CancellationToken cancellationToken = default)
        {
            ArgumentException.ThrowIfNullOrEmpty(path);

            return cancellationToken.IsCancellationRequested
                ? Task.FromCanceled(cancellationToken)
                : Core(path, bytes, cancellationToken);

            static async Task Core(string path, ReadOnlyMemory<byte> bytes, CancellationToken cancellationToken)
            {
                using SafeFileHandle fileHandle = OpenHandle(path, FileMode.Append, FileAccess.Write, FileShare.Read, FileOptions.Asynchronous);
                long fileOffset = RandomAccess.GetLength(fileHandle);
                await RandomAccess.WriteAtOffsetAsync(fileHandle, bytes, fileOffset, cancellationToken).ConfigureAwait(false);
            }
        }

        public static string[] ReadAllLines(string path)
            => ReadAllLines(path, Encoding.UTF8);

        public static string[] ReadAllLines(string path, Encoding encoding)
        {
            Validate(path, encoding);

            string? line;
            List<string> lines = new List<string>();

            using StreamReader sr = new StreamReader(path, encoding);
            while ((line = sr.ReadLine()) != null)
            {
                lines.Add(line);
            }

            return lines.ToArray();
        }

        public static IEnumerable<string> ReadLines(string path)
            => ReadLines(path, Encoding.UTF8);

        public static IEnumerable<string> ReadLines(string path, Encoding encoding)
        {
            Validate(path, encoding);

            return ReadLinesIterator.CreateIterator(path, encoding);
        }

        /// <summary>
        /// Asynchronously reads the lines of a file.
        /// </summary>
        /// <param name="path">The file to read.</param>
        /// <param name="cancellationToken">The token to monitor for cancellation requests. The default value is <see cref="CancellationToken.None"/>.</param>
        /// <returns>The async enumerable that represents all the lines of the file, or the lines that are the result of a query.</returns>
        public static IAsyncEnumerable<string> ReadLinesAsync(string path, CancellationToken cancellationToken = default)
            => ReadLinesAsync(path, Encoding.UTF8, cancellationToken);

        /// <summary>
        /// Asynchronously reads the lines of a file that has a specified encoding.
        /// </summary>
        /// <param name="path">The file to read.</param>
        /// <param name="encoding">The encoding that is applied to the contents of the file.</param>
        /// <param name="cancellationToken">The token to monitor for cancellation requests. The default value is <see cref="CancellationToken.None"/>.</param>
        /// <returns>The async enumerable that represents all the lines of the file, or the lines that are the result of a query.</returns>
        public static IAsyncEnumerable<string> ReadLinesAsync(string path, Encoding encoding, CancellationToken cancellationToken = default)
        {
            Validate(path, encoding);

            StreamReader sr = AsyncStreamReader(path, encoding); // Move first streamReader allocation here so to throw related file exception upfront, which will cause known leaking if user never actually foreach's over the enumerable
            return IterateFileLinesAsync(sr, path, encoding, cancellationToken);
        }

        public static void WriteAllLines(string path, string[] contents)
            => WriteAllLines(path, (IEnumerable<string>)contents);

        public static void WriteAllLines(string path, IEnumerable<string> contents)
            => WriteAllLines(path, contents, UTF8NoBOM);

        public static void WriteAllLines(string path, string[] contents, Encoding encoding)
            => WriteAllLines(path, (IEnumerable<string>)contents, encoding);

        public static void WriteAllLines(string path, IEnumerable<string> contents, Encoding encoding)
        {
            Validate(path, encoding);
            ArgumentNullException.ThrowIfNull(contents);
            InternalWriteAllLines(new StreamWriter(path, false, encoding), contents);
        }

        private static void InternalWriteAllLines(StreamWriter writer, IEnumerable<string> contents)
        {
            Debug.Assert(writer != null);
            Debug.Assert(contents != null);

            using (writer)
            {
                foreach (string line in contents)
                {
                    writer.WriteLine(line);
                }
            }
        }

        public static void AppendAllText(string path, string? contents)
            => AppendAllText(path, contents, UTF8NoBOM);

        /// <summary>
        /// Appends the specified string to the file, creating the file if it does not already exist.
        /// </summary>
        /// <param name="path">The file to append to.</param>
        /// <param name="contents">The characters to write to the file.</param>
        /// <exception cref="ArgumentNullException"><paramref name="path"/> is <see langword="null"/>.</exception>
        /// <exception cref="ArgumentException"><paramref name="path"/> is empty.</exception>
        /// <exception cref="PathTooLongException">The specified path, file name, or both exceed the system-defined maximum length.</exception>
        /// <exception cref="DirectoryNotFoundException">The specified path is invalid (for example, it is on an unmapped drive).</exception>
        /// <exception cref="IOException">An I/O error occurred while opening the file.</exception>
        /// <exception cref="UnauthorizedAccessException"><paramref name="path"/> specified a file that is read-only.</exception>
        /// <exception cref="UnauthorizedAccessException"><paramref name="path"/> specified a file that is hidden.</exception>
        /// <exception cref="UnauthorizedAccessException"><paramref name="path"/> specified a directory.</exception>
        /// <exception cref="UnauthorizedAccessException">This operation is not supported on the current platform.</exception>
        /// <exception cref="UnauthorizedAccessException">The caller does not have the required permission.</exception>
        /// <exception cref="NotSupportedException"><paramref name="path"/> is in an invalid format.</exception>
        /// <remarks>
        /// Given a string and a file path, this method opens the specified file, appends the string to the end of the file using the specified encoding,
        /// and then closes the file. The file handle is guaranteed to be closed by this method, even if exceptions are raised. The method creates the file
        /// if it doesn't exist, but it doesn't create new directories. Therefore, the value of the path parameter must contain existing directories.
        /// </remarks>
        public static void AppendAllText(string path, ReadOnlySpan<char> contents)
            => AppendAllText(path, contents, UTF8NoBOM);

        public static void AppendAllText(string path, string? contents, Encoding encoding)
        {
            Validate(path, encoding);

            WriteToFile(path, FileMode.Append, contents, encoding);
        }

        /// <summary>
        /// Appends the specified string to the file, creating the file if it does not already exist.
        /// </summary>
        /// <param name="path">The file to append to.</param>
        /// <param name="contents">The characters to write to the file.</param>
        /// <param name="encoding">The encoding to apply to the string.</param>
        /// <exception cref="ArgumentNullException"><paramref name="path"/> is <see langword="null"/>.</exception>
        /// <exception cref="ArgumentException"><paramref name="path"/> is empty.</exception>
        /// <exception cref="ArgumentNullException"><paramref name="encoding"/> is <see langword="null"/>.</exception>
        /// <exception cref="PathTooLongException">The specified path, file name, or both exceed the system-defined maximum length.</exception>
        /// <exception cref="DirectoryNotFoundException">The specified path is invalid (for example, it is on an unmapped drive).</exception>
        /// <exception cref="IOException">An I/O error occurred while opening the file.</exception>
        /// <exception cref="UnauthorizedAccessException"><paramref name="path"/> specified a file that is read-only.</exception>
        /// <exception cref="UnauthorizedAccessException"><paramref name="path"/> specified a file that is hidden.</exception>
        /// <exception cref="UnauthorizedAccessException"><paramref name="path"/> specified a directory.</exception>
        /// <exception cref="UnauthorizedAccessException">This operation is not supported on the current platform.</exception>
        /// <exception cref="UnauthorizedAccessException">The caller does not have the required permission.</exception>
        /// <exception cref="NotSupportedException"><paramref name="path"/> is in an invalid format.</exception>
        /// <remarks>
        /// Given a string and a file path, this method opens the specified file, appends the string to the end of the file using the specified encoding,
        /// and then closes the file. The file handle is guaranteed to be closed by this method, even if exceptions are raised. The method creates the file
        /// if it doesn't exist, but it doesn't create new directories. Therefore, the value of the path parameter must contain existing directories.
        /// </remarks>
        public static void AppendAllText(string path, ReadOnlySpan<char> contents, Encoding encoding)
        {
            Validate(path, encoding);

            WriteToFile(path, FileMode.Append, contents, encoding);
        }

        public static void AppendAllLines(string path, IEnumerable<string> contents)
            => AppendAllLines(path, contents, UTF8NoBOM);

        public static void AppendAllLines(string path, IEnumerable<string> contents, Encoding encoding)
        {
            Validate(path, encoding);
            ArgumentNullException.ThrowIfNull(contents);
            InternalWriteAllLines(new StreamWriter(path, true, encoding), contents);
        }

        public static void Replace(string sourceFileName, string destinationFileName, string? destinationBackupFileName)
            => Replace(sourceFileName, destinationFileName, destinationBackupFileName, ignoreMetadataErrors: false);

        public static void Replace(string sourceFileName, string destinationFileName, string? destinationBackupFileName, bool ignoreMetadataErrors)
        {
            ArgumentNullException.ThrowIfNull(sourceFileName);
            ArgumentNullException.ThrowIfNull(destinationFileName);

            FileSystem.ReplaceFile(
                Path.GetFullPath(sourceFileName),
                Path.GetFullPath(destinationFileName),
                destinationBackupFileName != null ? Path.GetFullPath(destinationBackupFileName) : null,
                ignoreMetadataErrors);
        }

        // Moves a specified file to a new location and potentially a new file name.
        // This method does work across volumes.
        //
        // The caller must have certain FileIOPermissions.  The caller must
        // have Read and Write permission to
        // sourceFileName and Write
        // permissions to destFileName.
        //
        public static void Move(string sourceFileName, string destFileName)
            => Move(sourceFileName, destFileName, false);

        public static void Move(string sourceFileName, string destFileName, bool overwrite)
        {
            ArgumentException.ThrowIfNullOrEmpty(sourceFileName);
            ArgumentException.ThrowIfNullOrEmpty(destFileName);

            string fullSourceFileName = Path.GetFullPath(sourceFileName);
            string fullDestFileName = Path.GetFullPath(destFileName);

            if (!FileSystem.FileExists(fullSourceFileName))
            {
                throw new FileNotFoundException(SR.Format(SR.IO_FileNotFound_FileName, fullSourceFileName), fullSourceFileName);
            }

            FileSystem.MoveFile(fullSourceFileName, fullDestFileName, overwrite);
        }

        [SupportedOSPlatform("windows")]
        public static void Encrypt(string path)
        {
            ArgumentNullException.ThrowIfNull(path);
            FileSystem.Encrypt(path);
        }

        [SupportedOSPlatform("windows")]
        public static void Decrypt(string path)
        {
            ArgumentNullException.ThrowIfNull(path);
            FileSystem.Decrypt(path);
        }

        // If we use the path-taking constructors we will not have FileOptions.Asynchronous set and
        // we will have asynchronous file access faked by the thread pool. We want the real thing.
        private static StreamReader AsyncStreamReader(string path, Encoding encoding)
            => new StreamReader(
                new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, DefaultBufferSize, FileOptions.Asynchronous | FileOptions.SequentialScan),
                encoding, detectEncodingFromByteOrderMarks: true);

        public static Task<string> ReadAllTextAsync(string path, CancellationToken cancellationToken = default)
            => ReadAllTextAsync(path, Encoding.UTF8, cancellationToken);

        public static Task<string> ReadAllTextAsync(string path, Encoding encoding, CancellationToken cancellationToken = default)
        {
            Validate(path, encoding);

            return cancellationToken.IsCancellationRequested
                ? Task.FromCanceled<string>(cancellationToken)
                : InternalReadAllTextAsync(path, encoding, cancellationToken);
        }

        private static async Task<string> InternalReadAllTextAsync(string path, Encoding encoding, CancellationToken cancellationToken)
        {
            Debug.Assert(!string.IsNullOrEmpty(path));
            Debug.Assert(encoding != null);

            char[]? buffer = null;
            StreamReader sr = AsyncStreamReader(path, encoding);
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                buffer = ArrayPool<char>.Shared.Rent(sr.CurrentEncoding.GetMaxCharCount(DefaultBufferSize));
                StringBuilder sb = new StringBuilder();
                while (true)
                {
                    int read = await sr.ReadAsync(new Memory<char>(buffer), cancellationToken).ConfigureAwait(false);
                    if (read == 0)
                    {
                        return sb.ToString();
                    }

                    sb.Append(buffer, 0, read);
                }
            }
            finally
            {
                sr.Dispose();
                if (buffer != null)
                {
                    ArrayPool<char>.Shared.Return(buffer);
                }
            }
        }

        public static Task WriteAllTextAsync(string path, string? contents, CancellationToken cancellationToken = default)
            => WriteAllTextAsync(path, contents, UTF8NoBOM, cancellationToken);

        /// <summary>
        /// Asynchronously creates a new file, writes the specified string to the file, and then closes the file.
        /// If the target file already exists, it is truncated and overwritten.
        /// </summary>
        /// <param name="path">The file to write to.</param>
        /// <param name="contents">The characters to write to the file.</param>
        /// <param name="cancellationToken">The token to monitor for cancellation requests. The default value is <see cref="CancellationToken.None"/>.</param>
        /// <returns>A task that represents the asynchronous write operation.</returns>
        /// <exception cref="OperationCanceledException">The cancellation token was canceled. This exception is stored into the returned task.</exception>
        public static Task WriteAllTextAsync(string path, ReadOnlyMemory<char> contents, CancellationToken cancellationToken = default)
            => WriteAllTextAsync(path, contents, UTF8NoBOM, cancellationToken);

        public static Task WriteAllTextAsync(string path, string? contents, Encoding encoding, CancellationToken cancellationToken = default)
            => WriteAllTextAsync(path, contents.AsMemory(), encoding, cancellationToken);

        /// <summary>
        /// Asynchronously creates a new file, writes the specified string to the file using the specified encoding, and then closes the file.
        /// If the target file already exists, it is truncated and overwritten.
        /// </summary>
        /// <param name="path">The file to write to.</param>
        /// <param name="contents">The characters to write to the file.</param>
        /// <param name="encoding">The encoding to apply to the string.</param>
        /// <param name="cancellationToken">The token to monitor for cancellation requests. The default value is <see cref="CancellationToken.None"/>.</param>
        /// <returns>A task that represents the asynchronous write operation.</returns>
        /// <exception cref="OperationCanceledException">The cancellation token was canceled. This exception is stored into the returned task.</exception>
        public static Task WriteAllTextAsync(string path, ReadOnlyMemory<char> contents, Encoding encoding, CancellationToken cancellationToken = default)
        {
            Validate(path, encoding);

            if (cancellationToken.IsCancellationRequested)
            {
                return Task.FromCanceled(cancellationToken);
            }

            return WriteToFileAsync(path, FileMode.Create, contents, encoding, cancellationToken);
        }

        public static Task<byte[]> ReadAllBytesAsync(string path, CancellationToken cancellationToken = default)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                return Task.FromCanceled<byte[]>(cancellationToken);
            }

            // SequentialScan is a perf hint that requires extra sys-call on non-Windows OSes.
            FileOptions options = FileOptions.Asynchronous | (OperatingSystem.IsWindows() ? FileOptions.SequentialScan : FileOptions.None);
            SafeFileHandle sfh = OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.Read, options);

            long fileLength = 0L;
            if (sfh.CanSeek && (fileLength = sfh.GetFileLength()) > Array.MaxLength)
            {
                sfh.Dispose();
                return Task.FromException<byte[]>(ExceptionDispatchInfo.SetCurrentStackTrace(new IOException(SR.IO_FileTooLong2GB)));
            }

#if DEBUG
            fileLength = 0; // improve the test coverage for InternalReadAllBytesUnknownLengthAsync
#endif

#pragma warning disable CA2025
            return fileLength > 0 ?
                InternalReadAllBytesAsync(sfh, (int)fileLength, cancellationToken) :
                InternalReadAllBytesUnknownLengthAsync(sfh, cancellationToken);
#pragma warning restore
        }

        private static async Task<byte[]> InternalReadAllBytesAsync(SafeFileHandle sfh, int count, CancellationToken cancellationToken)
        {
            using (sfh)
            {
                int index = 0;
                byte[] bytes = new byte[count];
                do
                {
                    int n = await RandomAccess.ReadAtOffsetAsync(sfh, bytes.AsMemory(index), index, cancellationToken).ConfigureAwait(false);
                    if (n == 0)
                    {
                        ThrowHelper.ThrowEndOfFileException();
                    }

                    index += n;
                } while (index < count);

                return bytes;
            }
        }

        private static async Task<byte[]> InternalReadAllBytesUnknownLengthAsync(SafeFileHandle sfh, CancellationToken cancellationToken)
        {
            byte[] rentedArray = ArrayPool<byte>.Shared.Rent(512);
            try
            {
                int bytesRead = 0;
                while (true)
                {
                    if (bytesRead == rentedArray.Length)
                    {
                        uint newLength = (uint)rentedArray.Length * 2;
                        if (newLength > Array.MaxLength)
                        {
                            newLength = (uint)Math.Max(Array.MaxLength, rentedArray.Length + 1);
                        }

                        byte[] tmp = ArrayPool<byte>.Shared.Rent((int)newLength);
                        Buffer.BlockCopy(rentedArray, 0, tmp, 0, bytesRead);

                        byte[] toReturn = rentedArray;
                        rentedArray = tmp;

                        ArrayPool<byte>.Shared.Return(toReturn);
                    }

                    Debug.Assert(bytesRead < rentedArray.Length);
                    int n = await RandomAccess.ReadAtOffsetAsync(sfh, rentedArray.AsMemory(bytesRead), bytesRead, cancellationToken).ConfigureAwait(false);
                    if (n == 0)
                    {
                        return rentedArray.AsSpan(0, bytesRead).ToArray();
                    }
                    bytesRead += n;
                }
            }
            finally
            {
                sfh.Dispose();
                ArrayPool<byte>.Shared.Return(rentedArray);
            }
        }

        public static Task WriteAllBytesAsync(string path, byte[] bytes, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(bytes);

            return WriteAllBytesAsync(path, new ReadOnlyMemory<byte>(bytes), cancellationToken);
        }

        /// <summary>
        /// Asynchronously creates a new file, writes the specified byte array to the file, and then closes the file. If the target file already exists, it is truncated and overwritten.
        /// </summary>
        /// <param name="path">The file to write to.</param>
        /// <param name="bytes">The bytes to write to the file.</param>
        /// <param name="cancellationToken">The token to monitor for cancellation requests. The default value is <see cref="CancellationToken.None"/>.</param>
        /// <returns>A task that represents the asynchronous write operation.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="path"/> is null.</exception>
        /// <exception cref="ArgumentException"><paramref name="path"/> is empty.</exception>
        /// <exception cref="OperationCanceledException">The cancellation token was canceled. This exception is stored into the returned task.</exception>
        public static Task WriteAllBytesAsync(string path, ReadOnlyMemory<byte> bytes, CancellationToken cancellationToken = default)
        {
            ArgumentException.ThrowIfNullOrEmpty(path);

            return cancellationToken.IsCancellationRequested
                ? Task.FromCanceled(cancellationToken)
                : Core(path, bytes, cancellationToken);

            static async Task Core(string path, ReadOnlyMemory<byte> bytes, CancellationToken cancellationToken)
            {
                using SafeFileHandle sfh = OpenHandle(path, FileMode.Create, FileAccess.Write, FileShare.Read, FileOptions.Asynchronous);
                await RandomAccess.WriteAtOffsetAsync(sfh, bytes, 0, cancellationToken).ConfigureAwait(false);
            }
        }

        public static Task<string[]> ReadAllLinesAsync(string path, CancellationToken cancellationToken = default)
            => ReadAllLinesAsync(path, Encoding.UTF8, cancellationToken);

        public static Task<string[]> ReadAllLinesAsync(string path, Encoding encoding, CancellationToken cancellationToken = default)
        {
            Validate(path, encoding);

            return cancellationToken.IsCancellationRequested
                ? Task.FromCanceled<string[]>(cancellationToken)
                : InternalReadAllLinesAsync(path, encoding, cancellationToken);
        }

        private static async Task<string[]> InternalReadAllLinesAsync(string path, Encoding encoding, CancellationToken cancellationToken)
        {
            Debug.Assert(!string.IsNullOrEmpty(path));
            Debug.Assert(encoding != null);

            using (StreamReader sr = AsyncStreamReader(path, encoding))
            {
                cancellationToken.ThrowIfCancellationRequested();
                string? line;
                List<string> lines = new List<string>();
                while ((line = await sr.ReadLineAsync(cancellationToken).ConfigureAwait(false)) != null)
                {
                    lines.Add(line);
                    cancellationToken.ThrowIfCancellationRequested();
                }

                return lines.ToArray();
            }
        }

        public static Task WriteAllLinesAsync(string path, IEnumerable<string> contents, CancellationToken cancellationToken = default)
            => WriteAllLinesAsync(path, contents, UTF8NoBOM, cancellationToken);

        public static Task WriteAllLinesAsync(string path, IEnumerable<string> contents, Encoding encoding, CancellationToken cancellationToken = default) =>
            WriteAllLinesAsync(path, contents, encoding, append: false, cancellationToken);

        private static Task WriteAllLinesAsync(string path, IEnumerable<string> contents, Encoding encoding, bool append, CancellationToken cancellationToken)
        {
            Validate(path, encoding);
            ArgumentNullException.ThrowIfNull(contents);
            if (cancellationToken.IsCancellationRequested)
            {
                return Task.FromCanceled(cancellationToken);
            }

            StreamWriter writer;
            try
            {
                writer = new StreamWriter(
                    new FileStream(path, append ? FileMode.Append : FileMode.Create, FileAccess.Write, FileShare.Read, DefaultBufferSize, FileOptions.Asynchronous),
                    encoding);
            }
            catch (Exception e)
            {
                return Task.FromException(e);
            }

            return InternalWriteAllLinesAsync(writer, contents, cancellationToken);
        }

        private static async Task InternalWriteAllLinesAsync(StreamWriter writer, IEnumerable<string> contents, CancellationToken cancellationToken)
        {
            Debug.Assert(writer != null);
            Debug.Assert(contents != null);

            using (writer)
            {
                foreach (string line in contents)
                {
                    await writer.WriteLineAsync(line.AsMemory(), cancellationToken).ConfigureAwait(false);
                }

                await writer.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
        }

        public static Task AppendAllTextAsync(string path, string? contents, CancellationToken cancellationToken = default)
            => AppendAllTextAsync(path, contents, UTF8NoBOM, cancellationToken);

        /// <summary>
        /// Asynchronously opens a file or creates a file if it does not already exist, appends the specified string to the file, and then closes the file.
        /// </summary>
        /// <param name="path">The file to append the specified string to.</param>
        /// <param name="contents">The characters to append to the file.</param>
        /// <param name="cancellationToken">The token to monitor for cancellation requests. The default value is <see cref="CancellationToken.None"/>.</param>
        /// <returns>A task that represents the asynchronous append operation.</returns>
        /// <exception cref="OperationCanceledException">The cancellation token was canceled. This exception is stored into the returned task.</exception>
        public static Task AppendAllTextAsync(string path, ReadOnlyMemory<char> contents, CancellationToken cancellationToken = default)
            => AppendAllTextAsync(path, contents, UTF8NoBOM, cancellationToken);

        public static Task AppendAllTextAsync(string path, string? contents, Encoding encoding, CancellationToken cancellationToken = default)
            => AppendAllTextAsync(path, contents.AsMemory(), encoding, cancellationToken);

        /// <summary>
        /// Asynchronously opens a file or creates the file if it does not already exist, appends the specified string to the file using the specified encoding, and then closes the file.
        /// </summary>
        /// <param name="path">The file to append the specified string to.</param>
        /// <param name="contents">The characters to append to the file.</param>
        /// <param name="encoding">The character encoding to use.</param>
        /// <param name="cancellationToken">The token to monitor for cancellation requests. The default value is <see cref="CancellationToken.None"/>.</param>
        /// <returns>A task that represents the asynchronous append operation.</returns>
        /// <exception cref="OperationCanceledException">The cancellation token was canceled. This exception is stored into the returned task.</exception>
        public static Task AppendAllTextAsync(string path, ReadOnlyMemory<char> contents, Encoding encoding, CancellationToken cancellationToken = default)
        {
            Validate(path, encoding);

            if (cancellationToken.IsCancellationRequested)
            {
                return Task.FromCanceled(cancellationToken);
            }

            return WriteToFileAsync(path, FileMode.Append, contents, encoding, cancellationToken);
        }

        public static Task AppendAllLinesAsync(string path, IEnumerable<string> contents, CancellationToken cancellationToken = default)
            => AppendAllLinesAsync(path, contents, UTF8NoBOM, cancellationToken);

        public static Task AppendAllLinesAsync(string path, IEnumerable<string> contents, Encoding encoding, CancellationToken cancellationToken = default) =>
            WriteAllLinesAsync(path, contents, encoding, append: true, cancellationToken);

        /// <summary>
        /// Creates a file symbolic link identified by <paramref name="path"/> that points to <paramref name="pathToTarget"/>.
        /// </summary>
        /// <param name="path">The path where the symbolic link should be created.</param>
        /// <param name="pathToTarget">The path of the target to which the symbolic link points.</param>
        /// <returns>A <see cref="FileInfo"/> instance that wraps the newly created file symbolic link.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="path"/> or <paramref name="pathToTarget"/> is <see langword="null"/>.</exception>
        /// <exception cref="ArgumentException"><paramref name="path"/> or <paramref name="pathToTarget"/> is empty.
        /// -or-
        /// <paramref name="path"/> or <paramref name="pathToTarget"/> contains a null character.</exception>
        /// <exception cref="IOException">A file or directory already exists in the location of <paramref name="path"/>.
        /// -or-
        /// An I/O error occurred.</exception>
        public static FileSystemInfo CreateSymbolicLink(string path, string pathToTarget)
        {
            string fullPath = Path.GetFullPath(path);
            FileSystem.VerifyValidPath(pathToTarget, nameof(pathToTarget));

            FileSystem.CreateSymbolicLink(path, pathToTarget, isDirectory: false);
            return new FileInfo(originalPath: path, fullPath: fullPath, isNormalized: true);
        }

        /// <summary>
        /// Gets the target of the specified file link.
        /// </summary>
        /// <param name="linkPath">The path of the file link.</param>
        /// <param name="returnFinalTarget"><see langword="true"/> to follow links to the final target; <see langword="false"/> to return the immediate next link.</param>
        /// <returns>A <see cref="FileInfo"/> instance if <paramref name="linkPath"/> exists, independently if the target exists or not. <see langword="null"/> if <paramref name="linkPath"/> is not a link.</returns>
        /// <exception cref="IOException">The file on <paramref name="linkPath"/> does not exist.
        /// -or-
        /// The link's file system entry type is inconsistent with that of its target.
        /// -or-
        /// Too many levels of symbolic links.</exception>
        /// <remarks>When <paramref name="returnFinalTarget"/> is <see langword="true"/>, the maximum number of symbolic links that are followed are 40 on Unix and 63 on Windows.</remarks>
        public static FileSystemInfo? ResolveLinkTarget(string linkPath, bool returnFinalTarget)
        {
            FileSystem.VerifyValidPath(linkPath, nameof(linkPath));
            return FileSystem.ResolveLinkTarget(linkPath, returnFinalTarget, isDirectory: false);
        }

        private static void Validate(string path, Encoding encoding)
        {
            ArgumentException.ThrowIfNullOrEmpty(path);
            ArgumentNullException.ThrowIfNull(encoding);
        }

        private static byte[] ReadAllBytesUnknownLength(SafeFileHandle sfh)
        {
            byte[]? rentedArray = null;
            Span<byte> buffer = stackalloc byte[512];
            try
            {
                int bytesRead = 0;
                while (true)
                {
                    if (bytesRead == buffer.Length)
                    {
                        uint newLength = (uint)buffer.Length * 2;
                        if (newLength > Array.MaxLength)
                        {
                            newLength = (uint)Math.Max(Array.MaxLength, buffer.Length + 1);
                        }

                        byte[] tmp = ArrayPool<byte>.Shared.Rent((int)newLength);
                        buffer.CopyTo(tmp);
                        byte[]? oldRentedArray = rentedArray;
                        buffer = rentedArray = tmp;
                        if (oldRentedArray != null)
                        {
                            ArrayPool<byte>.Shared.Return(oldRentedArray);
                        }
                    }

                    Debug.Assert(bytesRead < buffer.Length);
                    int n = RandomAccess.ReadAtOffset(sfh, buffer.Slice(bytesRead), bytesRead);
                    if (n == 0)
                    {
                        return buffer.Slice(0, bytesRead).ToArray();
                    }
                    bytesRead += n;
                }
            }
            finally
            {
                if (rentedArray != null)
                {
                    ArrayPool<byte>.Shared.Return(rentedArray);
                }
            }
        }

        private static void WriteToFile(string path, FileMode mode, ReadOnlySpan<char> contents, Encoding encoding)
        {
            ReadOnlySpan<byte> preamble = encoding.GetPreamble();
            int preambleSize = preamble.Length;

            using SafeFileHandle fileHandle = OpenHandle(path, mode, FileAccess.Write, FileShare.Read, FileOptions.None, GetPreallocationSize(mode, contents, encoding, preambleSize));
            long fileOffset = mode == FileMode.Append && fileHandle.CanSeek ? RandomAccess.GetLength(fileHandle) : 0;

            if (contents.IsEmpty)
            {
                if (preambleSize > 0 // even if the content is empty, we want to store the preamble
                    && fileOffset == 0) // if we're appending to a file that already has data, don't write the preamble.
                {
                    RandomAccess.WriteAtOffset(fileHandle, preamble, fileOffset);
                }
                return;
            }

            int bytesNeeded = checked(preambleSize + encoding.GetMaxByteCount(Math.Min(contents.Length, ChunkSize)));
            byte[]? rentedBytes = null;
            Span<byte> bytes = (uint)bytesNeeded <= 1024 ? stackalloc byte[1024] : (rentedBytes = ArrayPool<byte>.Shared.Rent(bytesNeeded));

            try
            {
                if (fileOffset == 0)
                {
                    preamble.CopyTo(bytes);
                }
                else
                {
                    preambleSize = 0; // don't append preamble to a non-empty file
                }

                Encoder encoder = encoding.GetEncoder();
                while (!contents.IsEmpty)
                {
                    ReadOnlySpan<char> toEncode = contents.Slice(0, Math.Min(contents.Length, ChunkSize));
                    contents = contents.Slice(toEncode.Length);
                    int encoded = encoder.GetBytes(toEncode, bytes.Slice(preambleSize), flush: contents.IsEmpty);
                    Span<byte> toStore = bytes.Slice(0, preambleSize + encoded);

                    RandomAccess.WriteAtOffset(fileHandle, toStore, fileOffset);

                    fileOffset += toStore.Length;
                    preambleSize = 0;
                }
            }
            finally
            {
                if (rentedBytes is not null)
                {
                    ArrayPool<byte>.Shared.Return(rentedBytes);
                }
            }
        }

        private static async Task WriteToFileAsync(string path, FileMode mode, ReadOnlyMemory<char> contents, Encoding encoding, CancellationToken cancellationToken)
        {
            ReadOnlyMemory<byte> preamble = encoding.GetPreamble();
            int preambleSize = preamble.Length;

            using SafeFileHandle fileHandle = OpenHandle(path, mode, FileAccess.Write, FileShare.Read, FileOptions.Asynchronous, GetPreallocationSize(mode, contents.Span, encoding, preambleSize));
            long fileOffset = mode == FileMode.Append && fileHandle.CanSeek ? RandomAccess.GetLength(fileHandle) : 0;

            if (contents.IsEmpty)
            {
                if (preambleSize > 0 // even if the content is empty, we want to store the preamble
                    && fileOffset == 0) // if we're appending to a file that already has data, don't write the preamble.
                {
                    await RandomAccess.WriteAtOffsetAsync(fileHandle, preamble, fileOffset, cancellationToken).ConfigureAwait(false);
                }
                return;
            }

            byte[] bytes = ArrayPool<byte>.Shared.Rent(preambleSize + encoding.GetMaxByteCount(Math.Min(contents.Length, ChunkSize)));

            try
            {
                if (fileOffset == 0)
                {
                    preamble.CopyTo(bytes);
                }
                else
                {
                    preambleSize = 0; // don't append preamble to a non-empty file
                }

                Encoder encoder = encoding.GetEncoder();
                while (!contents.IsEmpty)
                {
                    ReadOnlyMemory<char> toEncode = contents.Slice(0, Math.Min(contents.Length, ChunkSize));
                    contents = contents.Slice(toEncode.Length);
                    int encoded = encoder.GetBytes(toEncode.Span, bytes.AsSpan(preambleSize), flush: contents.IsEmpty);
                    ReadOnlyMemory<byte> toStore = new ReadOnlyMemory<byte>(bytes, 0, preambleSize + encoded);

                    await RandomAccess.WriteAtOffsetAsync(fileHandle, toStore, fileOffset, cancellationToken).ConfigureAwait(false);

                    fileOffset += toStore.Length;
                    preambleSize = 0;
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(bytes);
            }
        }

        private static long GetPreallocationSize(FileMode mode, ReadOnlySpan<char> contents, Encoding encoding, int preambleSize)
        {
            // for a single write operation, setting preallocationSize has no perf benefit, as it requires an additional sys-call
            if (contents.Length < ChunkSize)
            {
                return 0;
            }

            // preallocationSize is ignored for Append mode, there is no need to spend cycles on GetByteCount
            if (mode == FileMode.Append)
            {
                return 0;
            }

            return preambleSize + encoding.GetByteCount(contents);
        }

        private static async IAsyncEnumerable<string> IterateFileLinesAsync(StreamReader sr, string path, Encoding encoding, CancellationToken ctEnumerable, [EnumeratorCancellation] CancellationToken ctEnumerator = default)
        {
            if (!sr.BaseStream.CanRead)
            {
                sr = AsyncStreamReader(path, encoding);
            }

            using (sr)
            {
                using CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(ctEnumerable, ctEnumerator);
                string? line;
                while ((line = await sr.ReadLineAsync(cts.Token).ConfigureAwait(false)) is not null)
                {
                    yield return line;
                }
            }
        }
    }
}
