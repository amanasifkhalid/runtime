// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Security;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace System.IO.Pipes
{
    public abstract partial class PipeStream : Stream
    {
        internal const string AnonymousPipeName = "anonymous";

        private SafePipeHandle? _handle;
        private bool _canRead;
        private bool _canWrite;
        private bool _isAsync;
        private bool _isCurrentUserOnly;
        private bool _isMessageComplete;
        private bool _isFromExistingHandle;
        private bool _isHandleExposed;
        private PipeTransmissionMode _readMode;
        private PipeTransmissionMode _transmissionMode;
        private PipeDirection _pipeDirection;
        private uint _outBufferSize;
        private PipeState _state;

        protected PipeStream(PipeDirection direction, int bufferSize)
        {
            if (direction < PipeDirection.In || direction > PipeDirection.InOut)
            {
                throw new ArgumentOutOfRangeException(nameof(direction), SR.ArgumentOutOfRange_DirectionModeInOutOrInOut);
            }
            ArgumentOutOfRangeException.ThrowIfNegative(bufferSize);

            Init(direction, PipeTransmissionMode.Byte, (uint)bufferSize);
        }

        protected PipeStream(PipeDirection direction, PipeTransmissionMode transmissionMode, int outBufferSize)
        {
            if (direction < PipeDirection.In || direction > PipeDirection.InOut)
            {
                throw new ArgumentOutOfRangeException(nameof(direction), SR.ArgumentOutOfRange_DirectionModeInOutOrInOut);
            }
            if (transmissionMode < PipeTransmissionMode.Byte || transmissionMode > PipeTransmissionMode.Message)
            {
                throw new ArgumentOutOfRangeException(nameof(transmissionMode), SR.ArgumentOutOfRange_TransmissionModeByteOrMsg);
            }
            ArgumentOutOfRangeException.ThrowIfNegative(outBufferSize);

            Init(direction, transmissionMode, (uint)outBufferSize);
        }

        private void Init(PipeDirection direction, PipeTransmissionMode transmissionMode, uint outBufferSize)
        {
            Debug.Assert(direction >= PipeDirection.In && direction <= PipeDirection.InOut, "invalid pipe direction");
            Debug.Assert(transmissionMode >= PipeTransmissionMode.Byte && transmissionMode <= PipeTransmissionMode.Message, "transmissionMode is out of range");
            Debug.Assert(outBufferSize >= 0, "outBufferSize is negative");

            // always defaults to this until overridden
            _readMode = transmissionMode;
            _transmissionMode = transmissionMode;

            _pipeDirection = direction;

            if ((_pipeDirection & PipeDirection.In) != 0)
            {
                _canRead = true;
            }
            if ((_pipeDirection & PipeDirection.Out) != 0)
            {
                _canWrite = true;
            }

            _outBufferSize = outBufferSize;

            // This should always default to true
            _isMessageComplete = true;

            _state = PipeState.WaitingToConnect;
        }

        // Once a PipeStream has a handle ready, it should call this method to set up the PipeStream.  If
        // the pipe is in a connected state already, it should also set the IsConnected (protected) property.
        // This method may also be called to uninitialize a handle, setting it to null.
        protected void InitializeHandle(SafePipeHandle? handle, bool isExposed, bool isAsync)
        {
            if (isAsync && handle != null)
            {
                InitializeAsyncHandle(handle);
            }

            _handle = handle;
            _isAsync = isAsync;

            // track these separately; _isHandleExposed will get updated if accessed though the property
            _isHandleExposed = isExposed;
            _isFromExistingHandle = isExposed;
        }

        [Conditional("DEBUG")]
        private static void DebugAssertHandleValid(SafePipeHandle handle)
        {
            Debug.Assert(handle != null, "handle is null");
            Debug.Assert(!handle.IsClosed, "handle is closed");
        }

        // Reads a byte from the pipe stream.  Returns the byte cast to an int
        // or -1 if the connection has been broken.
        public override int ReadByte()
        {
            byte b = 0;
            return Read(new Span<byte>(ref b)) > 0 ? b : -1;
        }

        public override void WriteByte(byte value)
        {
            Write([value]);
        }

        public override void Flush()
        {
            CheckWriteOperations();

            // Does nothing on PipeStreams.  We cannot call Interop.FlushFileBuffers here because we can deadlock
            // if the other end of the pipe is no longer interested in reading from the pipe.
        }

        public override Task FlushAsync(CancellationToken cancellationToken)
        {
            try
            {
                Flush();
                return Task.CompletedTask;
            }
            catch (Exception ex)
            {
                return Task.FromException(ex);
            }
        }

        protected override void Dispose(bool disposing)
        {
            // Mark the pipe as closed before calling DisposeCore. That way, other threads that might
            // be synchronizing on shared resources disposed of in DisposeCore will be guaranteed to
            // see the closed state after that synchronization.
            _state = PipeState.Closed;

            try
            {
                // Nothing will be done differently based on whether we are
                // disposing vs. finalizing.
                if (_handle != null && !_handle.IsClosed)
                {
                    _handle.Dispose();
                }

                DisposeCore(disposing);
            }
            finally
            {
                base.Dispose(disposing);
            }
        }

        // ********************** Public Properties *********************** //

        // APIs use coarser definition of connected, but these map to internal
        // Connected/Disconnected states. Note that setter is protected; only
        // intended to be called by custom PipeStream concrete children
        public bool IsConnected
        {
            get
            {
                return State == PipeState.Connected;
            }
            protected set
            {
                _state = (value) ? PipeState.Connected : PipeState.Disconnected;
            }
        }

        public bool IsAsync
        {
            get { return _isAsync; }
        }

        // Set by the most recent call to Read or EndRead.  Will be false if there are more buffer in the
        // message, otherwise it is set to true.
        public bool IsMessageComplete
        {
            get
            {
                // omitting pipe broken exception to allow reader to finish getting message
                if (_state == PipeState.WaitingToConnect)
                {
                    throw new InvalidOperationException(SR.InvalidOperation_PipeNotYetConnected);
                }
                if (_state == PipeState.Disconnected)
                {
                    throw new InvalidOperationException(SR.InvalidOperation_PipeDisconnected);
                }
                if (CheckOperationsRequiresSetHandle && _handle == null)
                {
                    throw new InvalidOperationException(SR.InvalidOperation_PipeHandleNotSet);
                }

                if ((_state == PipeState.Closed) || (_handle != null && _handle.IsClosed))
                {
                    throw Error.GetPipeNotOpen();
                }
                // don't need to check transmission mode; just care about read mode. Always use
                // cached mode; otherwise could throw for valid message when other side is shutting down
                if (_readMode != PipeTransmissionMode.Message)
                {
                    throw new InvalidOperationException(SR.InvalidOperation_PipeReadModeNotMessage);
                }

                return _isMessageComplete;
            }
        }

        internal void UpdateMessageCompletion(bool completion)
        {
            // Set message complete to true because the pipe is broken as well.
            // Need this to signal to readers to stop reading.
            _isMessageComplete = (completion || _state == PipeState.Broken);
        }

        public SafePipeHandle SafePipeHandle
        {
            get
            {
                if (_handle == null)
                {
                    throw new InvalidOperationException(SR.InvalidOperation_PipeHandleNotSet);
                }
                if (_handle.IsClosed)
                {
                    throw Error.GetPipeNotOpen();
                }

                _isHandleExposed = true;
                return _handle;
            }
        }

        internal SafePipeHandle? InternalHandle
        {
            get
            {
                return _handle;
            }
        }

        protected bool IsHandleExposed
        {
            get
            {
                return _isHandleExposed;
            }
        }

        public override bool CanRead
        {
            get
            {
                return _canRead;
            }
        }

        public override bool CanWrite
        {
            get
            {
                return _canWrite;
            }
        }

        public override bool CanSeek
        {
            get
            {
                return false;
            }
        }

        public override long Length
        {
            get
            {
                throw Error.GetSeekNotSupported();
            }
        }

        public override long Position
        {
            get
            {
                throw Error.GetSeekNotSupported();
            }
            set
            {
                throw Error.GetSeekNotSupported();
            }
        }

        public override void SetLength(long value)
        {
            throw Error.GetSeekNotSupported();
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw Error.GetSeekNotSupported();
        }

        // anonymous pipe ends and named pipe server can get/set properties when broken
        // or connected. Named client overrides
        protected internal virtual void CheckPipePropertyOperations()
        {
            if (CheckOperationsRequiresSetHandle && _handle == null)
            {
                throw new InvalidOperationException(SR.InvalidOperation_PipeHandleNotSet);
            }

            // these throw object disposed
            if ((_state == PipeState.Closed) || (_handle != null && _handle.IsClosed))
            {
                throw Error.GetPipeNotOpen();
            }
        }

        // Reads can be done in Connected and Broken. In the latter,
        // read returns 0 bytes
        protected internal void CheckReadOperations()
        {
            // Invalid operation
            if (_state == PipeState.WaitingToConnect)
            {
                throw new InvalidOperationException(SR.InvalidOperation_PipeNotYetConnected);
            }
            if (_state == PipeState.Disconnected)
            {
                throw new InvalidOperationException(SR.InvalidOperation_PipeDisconnected);
            }
            if (CheckOperationsRequiresSetHandle && _handle == null)
            {
                throw new InvalidOperationException(SR.InvalidOperation_PipeHandleNotSet);
            }

            // these throw object disposed
            if ((_state == PipeState.Closed) || (_handle != null && _handle.IsClosed))
            {
                throw Error.GetPipeNotOpen();
            }
        }

        // Writes can only be done in connected state
        protected internal void CheckWriteOperations()
        {
            // Invalid operation
            if (_state == PipeState.WaitingToConnect)
            {
                throw new InvalidOperationException(SR.InvalidOperation_PipeNotYetConnected);
            }
            if (_state == PipeState.Disconnected)
            {
                throw new InvalidOperationException(SR.InvalidOperation_PipeDisconnected);
            }
            if (CheckOperationsRequiresSetHandle && _handle == null)
            {
                throw new InvalidOperationException(SR.InvalidOperation_PipeHandleNotSet);
            }

            // IOException
            if (_state == PipeState.Broken)
            {
                throw new IOException(SR.IO_PipeBroken);
            }

            // these throw object disposed
            if ((_state == PipeState.Closed) || (_handle != null && _handle.IsClosed))
            {
                throw Error.GetPipeNotOpen();
            }
        }

        internal PipeState State
        {
            get
            {
                return _state;
            }
            set
            {
                _state = value;
            }
        }

        internal bool IsCurrentUserOnly
        {
            get
            {
                return _isCurrentUserOnly;
            }
            set
            {
                _isCurrentUserOnly = value;
            }
        }
    }
}
