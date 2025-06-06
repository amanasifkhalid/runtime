// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics;
using System.Globalization;
using System.Net.WebSockets;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace System.Net
{
    public sealed partial class HttpListenerRequest
    {
        private CookieCollection? _cookies;
        private bool? _keepAlive;
        private string? _rawUrl;
        private Uri? _requestUri;
        private Version _version;

        public string[]? AcceptTypes => Helpers.ParseMultivalueHeader(Headers[HttpKnownHeaderNames.Accept]!);

        public string[]? UserLanguages => Helpers.ParseMultivalueHeader(Headers[HttpKnownHeaderNames.AcceptLanguage]!);

        private CookieCollection ParseCookies(Uri? uri, string setCookieHeader)
        {
            if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "uri:" + uri + " setCookieHeader:" + setCookieHeader);
            CookieCollection cookies = new CookieCollection();
            CookieParser parser = new CookieParser(setCookieHeader);
            while (true)
            {
                Cookie? cookie = parser.GetServer();
                if (cookie == null)
                {
                    // EOF, done.
                    break;
                }
                if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "CookieParser returned cookie: " + cookie.ToString());
                if (cookie.Name.Length == 0)
                {
                    continue;
                }

                cookies.InternalAdd(cookie, true);
            }
            return cookies;
        }

        public CookieCollection Cookies
        {
            get
            {
                if (_cookies == null)
                {
                    string? cookieString = Headers[HttpKnownHeaderNames.Cookie];
                    if (!string.IsNullOrEmpty(cookieString))
                    {
                        _cookies = ParseCookies(RequestUri, cookieString);
                    }

                    _cookies ??= new CookieCollection();
                }
                return _cookies;
            }
        }

        public Encoding ContentEncoding
        {
            get
            {
                if (UserAgent != null && CultureInfo.InvariantCulture.CompareInfo.IsPrefix(UserAgent, "UP"))
                {
                    string? postDataCharset = Headers["x-up-devcap-post-charset"];
                    if (postDataCharset != null && postDataCharset.Length > 0)
                    {
                        try
                        {
                            return Encoding.GetEncoding(postDataCharset);
                        }
                        catch (ArgumentException)
                        {
                        }
                    }
                }
                if (HasEntityBody)
                {
                    if (ContentType != null)
                    {
                        string? charSet = Helpers.GetCharSetValueFromHeader(ContentType);
                        if (charSet != null)
                        {
                            try
                            {
                                return Encoding.GetEncoding(charSet);
                            }
                            catch (ArgumentException)
                            {
                            }
                        }
                    }
                }
                return Encoding.Default;
            }
        }

        public string? ContentType => Headers[HttpKnownHeaderNames.ContentType];

        public bool IsLocal => LocalEndPoint!.Address.Equals(RemoteEndPoint!.Address);

        public bool IsWebSocketRequest
        {
            get
            {
                if (!SupportsWebSockets)
                {
                    return false;
                }

                bool foundConnectionUpgradeHeader = false;
                if (string.IsNullOrEmpty(Headers[HttpKnownHeaderNames.Connection]) || string.IsNullOrEmpty(Headers[HttpKnownHeaderNames.Upgrade]))
                {
                    return false;
                }

                foreach (string connection in Headers.GetValues(HttpKnownHeaderNames.Connection)!)
                {
                    if (string.Equals(connection, HttpKnownHeaderNames.Upgrade, StringComparison.OrdinalIgnoreCase))
                    {
                        foundConnectionUpgradeHeader = true;
                        break;
                    }
                }

                if (!foundConnectionUpgradeHeader)
                {
                    return false;
                }

                foreach (string upgrade in Headers.GetValues(HttpKnownHeaderNames.Upgrade)!)
                {
                    if (string.Equals(upgrade, HttpWebSocket.WebSocketUpgradeToken, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }

                return false;
            }
        }

        public bool KeepAlive
        {
            get
            {
                if (!_keepAlive.HasValue)
                {
                    string? header = Headers[HttpKnownHeaderNames.ProxyConnection];
                    if (string.IsNullOrEmpty(header))
                    {
                        header = Headers[HttpKnownHeaderNames.Connection];
                    }
                    if (string.IsNullOrEmpty(header))
                    {
                        if (ProtocolVersion >= HttpVersion.Version11)
                        {
                            _keepAlive = true;
                        }
                        else
                        {
                            header = Headers[HttpKnownHeaderNames.KeepAlive];
                            _keepAlive = !string.IsNullOrEmpty(header);
                        }
                    }
                    else
                    {
                        header = header.ToLowerInvariant();
                        _keepAlive =
                            header.IndexOf("close", StringComparison.OrdinalIgnoreCase) < 0 ||
                            header.Contains("keep-alive", StringComparison.OrdinalIgnoreCase);
                    }
                }

                if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "_keepAlive=" + _keepAlive);
                return _keepAlive.Value;
            }
        }

        public NameValueCollection QueryString
        {
            get
            {
                NameValueCollection queryString = new NameValueCollection();
                Helpers.FillFromString(queryString, Url!.Query, true, ContentEncoding);
                return queryString;
            }
        }

        public string? RawUrl => _rawUrl;

        private string RequestScheme => IsSecureConnection ? UriScheme.Https : UriScheme.Http;

        public string? UserAgent => Headers[HttpKnownHeaderNames.UserAgent];

        public string UserHostAddress => LocalEndPoint!.ToString();

        public string UserHostName => Headers[HttpKnownHeaderNames.Host]!;

        public Uri? UrlReferrer
        {
            get
            {
                string? referrer = Headers[HttpKnownHeaderNames.Referer];
                if (referrer == null)
                {
                    return null;
                }

                bool success = Uri.TryCreate(referrer, UriKind.RelativeOrAbsolute, out Uri? urlReferrer);
                return success ? urlReferrer : null;
            }
        }

        public Uri? Url => RequestUri;

        public Version ProtocolVersion => _version;

        public X509Certificate2? GetClientCertificate()
        {
            if (ClientCertState == ListenerClientCertState.InProgress)
                throw new InvalidOperationException(SR.Format(SR.net_listener_callinprogress, $"{nameof(GetClientCertificate)}()/{nameof(BeginGetClientCertificate)}()"));
            ClientCertState = ListenerClientCertState.InProgress;

            GetClientCertificateCore();

            ClientCertState = ListenerClientCertState.Completed;
            if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, $"_clientCertificate:{ClientCertificate}");

            return ClientCertificate;
        }

        public IAsyncResult BeginGetClientCertificate(AsyncCallback? requestCallback, object? state)
        {
            if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this);
            if (ClientCertState == ListenerClientCertState.InProgress)
                throw new InvalidOperationException(SR.Format(SR.net_listener_callinprogress, $"{nameof(GetClientCertificate)}()/{nameof(BeginGetClientCertificate)}()"));
            ClientCertState = ListenerClientCertState.InProgress;

            return BeginGetClientCertificateCore(requestCallback, state);
        }

        public Task<X509Certificate2?> GetClientCertificateAsync()
        {
            return Task.Factory.FromAsync(
                (callback, state) => ((HttpListenerRequest)state!).BeginGetClientCertificate(callback, state),
                iar => ((HttpListenerRequest)iar.AsyncState!).EndGetClientCertificate(iar),
                this);
        }

        internal ListenerClientCertState ClientCertState { get; set; } = ListenerClientCertState.NotInitialized;
        internal X509Certificate2? ClientCertificate { get; set; }

        public int ClientCertificateError
        {
            get
            {
                if (ClientCertState == ListenerClientCertState.NotInitialized)
                    throw new InvalidOperationException(SR.Format(SR.net_listener_mustcall, "GetClientCertificate()/BeginGetClientCertificate()"));
                else if (ClientCertState == ListenerClientCertState.InProgress)
                    throw new InvalidOperationException(SR.Format(SR.net_listener_mustcompletecall, "GetClientCertificate()/BeginGetClientCertificate()"));

                return GetClientCertificateErrorCore();
            }
        }

        private static class Helpers
        {
            //
            // Get attribute off header value
            //
            internal static string? GetCharSetValueFromHeader(string headerValue)
            {
                const string AttrName = "charset";

                if (headerValue == null)
                    return null;

                int l = headerValue.Length;
                int k = AttrName.Length;

                // find properly separated attribute name
                int i = 1; // start searching from 1

                while (i < l)
                {
                    i = CultureInfo.InvariantCulture.CompareInfo.IndexOf(headerValue, AttrName, i, CompareOptions.IgnoreCase);
                    if (i < 0)
                        break;
                    if (i + k >= l)
                        break;

                    char chPrev = headerValue[i - 1];
                    char chNext = headerValue[i + k];
                    if ((chPrev == ';' || chPrev == ',' || char.IsWhiteSpace(chPrev)) && (chNext == '=' || char.IsWhiteSpace(chNext)))
                        break;

                    i += k;
                }

                if (i < 0 || i >= l)
                    return null;

                // skip to '=' and the following whitespace
                i += k;
                while (i < l && char.IsWhiteSpace(headerValue[i]))
                    i++;
                if (i >= l || headerValue[i] != '=')
                    return null;
                i++;
                while (i < l && char.IsWhiteSpace(headerValue[i]))
                    i++;
                if (i >= l)
                    return null;

                // parse the value
                string? attrValue;

                int j;

                if (i < l && headerValue[i] == '"')
                {
                    if (i == l - 1)
                        return null;
                    j = headerValue.IndexOf('"', i + 1);
                    if (j < 0 || j == i + 1)
                        return null;

                    attrValue = headerValue.AsSpan(i + 1, j - i - 1).Trim().ToString();
                }
                else
                {
                    for (j = i; j < l; j++)
                    {
                        if (headerValue[j] == ';')
                            break;
                    }

                    if (j == i)
                        return null;

                    attrValue = headerValue.AsSpan(i, j - i).Trim().ToString();
                }

                return attrValue;
            }

            internal static string[]? ParseMultivalueHeader(string s)
            {
                if (s == null)
                    return null;

                int l = s.Length;

                // collect comma-separated values into list

                List<string> values = new List<string>();
                int i = 0;

                while (i < l)
                {
                    // find next ,
                    int ci = s.IndexOf(',', i);
                    if (ci < 0)
                        ci = l;

                    // append corresponding server value
                    values.Add(s.Substring(i, ci - i));

                    // move to next
                    i = ci + 1;

                    // skip leading space
                    if (i < l && s[i] == ' ')
                        i++;
                }

                // return list as array of strings

                int n = values.Count;
                string[] strings;

                // if n is 0 that means s was empty string

                if (n == 0)
                {
                    strings = new string[1];
                    strings[0] = string.Empty;
                }
                else
                {
                    strings = new string[n];
                    values.CopyTo(0, strings, 0, n);
                }
                return strings;
            }


            private static string UrlDecodeStringFromStringInternal(string s, Encoding e)
            {
                int count = s.Length;
                UrlDecoder helper = new UrlDecoder(count, e);

                // go through the string's chars collapsing %XX and %uXXXX and
                // appending each char as char, with exception of %XX constructs
                // that are appended as bytes

                for (int pos = 0; pos < count; pos++)
                {
                    char ch = s[pos];

                    if (ch == '+')
                    {
                        ch = ' ';
                    }
                    else if (ch == '%' && pos < count - 2)
                    {
                        if (s[pos + 1] == 'u' && pos < count - 5)
                        {
                            int h1 = HexConverter.FromChar(s[pos + 2]);
                            int h2 = HexConverter.FromChar(s[pos + 3]);
                            int h3 = HexConverter.FromChar(s[pos + 4]);
                            int h4 = HexConverter.FromChar(s[pos + 5]);

                            if ((h1 | h2 | h3 | h4) != 0xFF)
                            {   // valid 4 hex chars
                                ch = (char)((h1 << 12) | (h2 << 8) | (h3 << 4) | h4);
                                pos += 5;

                                // only add as char
                                helper.AddChar(ch);
                                continue;
                            }
                        }
                        else
                        {
                            int h1 = HexConverter.FromChar(s[pos + 1]);
                            int h2 = HexConverter.FromChar(s[pos + 2]);

                            if ((h1 | h2) != 0xFF)
                            {     // valid 2 hex chars
                                byte b = (byte)((h1 << 4) | h2);
                                pos += 2;

                                // don't add as char
                                helper.AddByte(b);
                                continue;
                            }
                        }
                    }

                    if ((ch & 0xFF80) == 0)
                        helper.AddByte((byte)ch); // 7 bit have to go as bytes because of Unicode
                    else
                        helper.AddChar(ch);
                }

                return helper.GetString();
            }

            private sealed class UrlDecoder
            {
                private readonly int _bufferSize;

                // Accumulate characters in a special array
                private int _numChars;
                private readonly char[] _charBuffer;

                // Accumulate bytes for decoding into characters in a special array
                private int _numBytes;
                private byte[]? _byteBuffer;

                // Encoding to convert chars to bytes
                private readonly Encoding _encoding;

                private void FlushBytes()
                {
                    if (_numBytes > 0)
                    {
                        _numChars += _encoding.GetChars(_byteBuffer!, 0, _numBytes, _charBuffer, _numChars);
                        _numBytes = 0;
                    }
                }

                internal UrlDecoder(int bufferSize, Encoding encoding)
                {
                    _bufferSize = bufferSize;
                    _encoding = encoding;

                    _charBuffer = new char[bufferSize];
                    // byte buffer created on demand
                }

                internal void AddChar(char ch)
                {
                    if (_numBytes > 0)
                        FlushBytes();

                    _charBuffer[_numChars++] = ch;
                }

                internal void AddByte(byte b)
                {
                    _byteBuffer ??= new byte[_bufferSize];

                    _byteBuffer[_numBytes++] = b;
                }

                internal string GetString()
                {
                    if (_numBytes > 0)
                        FlushBytes();

                    if (_numChars > 0)
                        return new string(_charBuffer, 0, _numChars);
                    else
                        return string.Empty;
                }
            }


            internal static void FillFromString(NameValueCollection nvc, string s, bool urlencoded, Encoding encoding)
            {
                int i = s.StartsWith('?') ? 1 : 0;
                int l = s.Length;

                while (i < l)
                {
                    // find next & while noting first = on the way (and if there are more)

                    int si = i;
                    int ti = -1;

                    while (i < l)
                    {
                        char ch = s[i];

                        if (ch == '=')
                        {
                            if (ti < 0)
                                ti = i;
                        }
                        else if (ch == '&')
                        {
                            break;
                        }

                        i++;
                    }

                    // extract the name / value pair

                    string? name = null;
                    string? value;

                    if (ti >= 0)
                    {
                        name = s.Substring(si, ti - si);
                        value = s.Substring(ti + 1, i - ti - 1);
                    }
                    else
                    {
                        value = s.Substring(si, i - si);
                    }

                    // add name / value pair to the collection

                    if (urlencoded)
                        nvc.Add(
                           name == null ? null : UrlDecodeStringFromStringInternal(name, encoding),
                           UrlDecodeStringFromStringInternal(value, encoding));
                    else
                        nvc.Add(name, value);

                    // trailing '&'

                    if (i == l - 1 && s[i] == '&')
                        nvc.Add(null, "");

                    i++;
                }
            }
        }
    }
}
