namespace IpMatcher
{
    using System;
    using System.Collections;
    using System.Collections.Generic;
    using System.Linq;
    using System.Net;
    using System.Text;
    using Caching;

    /// <summary>
    /// IP address matcher.
    /// Thread safe: all public members may be called concurrently from multiple threads.
    /// Dispose the matcher when it is no longer needed to release its match cache and the cache's background expiration task.
    /// </summary>
    public class Matcher : IDisposable
    {
        #region Public-Members

        /// <summary>
        /// Method to invoke to send log messages.
        /// </summary>
        public Action<string> Logger = null;

        /// <summary>
        /// Maximum number of matched IP addresses held in the match cache.
        /// The cache uses least-recently-used eviction, so memory stays bounded regardless of how many distinct addresses are matched.
        /// Default is 4096.  Minimum is 0, which disables the match cache.  There is no maximum.
        /// Changing the value discards any cached entries.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when the value is less than 0.</exception>
        public int CacheCapacity
        {
            get
            {
                return _CacheCapacity;
            }
            set
            {
                if (value < 0) throw new ArgumentOutOfRangeException(nameof(CacheCapacity), "Cache capacity must be zero or greater.");

                LRUCache<string, DateTime> previous = null;

                lock (_CacheLock)
                {
                    _CacheCapacity = value;
                    previous = _Cache;
                    _Cache = null;
                }

                DisposeCache(previous);
            }
        }

        /// <summary>
        /// Number of matched IP addresses currently held in the match cache.  Never exceeds <see cref="CacheCapacity"/>.
        /// </summary>
        public int CacheCount
        {
            get
            {
                LRUCache<string, DateTime> cache = GetCache(false);
                if (cache == null) return 0;

                try
                {
                    return cache.Count();
                }
                catch (ObjectDisposedException)
                {
                    return 0;
                }
            }
        }

        /// <summary>
        /// Name of the match cache, reported as the cache.name label by the Caching library's telemetry (meter and activity source "Caching").
        /// </summary>
        public static readonly string CacheName = "ipmatcher";

        #endregion

        #region Private-Members

        private string _Header = "[IpMatcher] ";
        private readonly object _AddressLock = new object();
        private List<Address> _Addresses = new List<Address>();
        private readonly object _CacheLock = new object();
        private LRUCache<string, DateTime> _Cache = null;
        private int _CacheCapacity = 4096;
        private bool _Disposed = false;
        private static readonly byte[] _ContiguousPatterns = { 0x80, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC, 0xFE, 0xFF };

        #endregion

        #region Constructors-and-Factories

        /// <summary>
        /// Instantiate the IP address matcher with the default match cache capacity (4096).
        /// </summary>
        public Matcher()
        {

        }

        /// <summary>
        /// Instantiate the IP address matcher.
        /// </summary>
        /// <param name="cacheCapacity">Maximum number of matched IP addresses held in the match cache.  Minimum 0 (disables the cache).</param>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when cacheCapacity is less than 0.</exception>
        public Matcher(int cacheCapacity)
        {
            CacheCapacity = cacheCapacity;
        }

        #endregion

        #region Public-Methods

        /// <summary>
        /// Add a node to the match list.
        /// </summary>
        /// <param name="ip">The IP address, i.e. 192.168.1.0.</param>
        /// <param name="netmask">The netmask, i.e. 255.255.255.0.</param>
        /// <exception cref="ArgumentNullException">Thrown when ip or netmask is null or empty.</exception>
        /// <exception cref="FormatException">Thrown when ip or netmask is not a valid IP address.</exception>
        /// <exception cref="ArgumentException">Thrown when ip and netmask belong to different address families.</exception>
        public void Add(string ip, string netmask)
        {
            if (String.IsNullOrEmpty(ip)) throw new ArgumentNullException(nameof(ip));
            if (String.IsNullOrEmpty(netmask)) throw new ArgumentNullException(nameof(netmask));

            ip = IPAddress.Parse(ip).ToString();
            netmask = IPAddress.Parse(netmask).ToString();

            string baseAddress = GetBaseIpAddress(ip, netmask);
            if (Exists(baseAddress, netmask)) return;

            lock (_AddressLock)
            {
                _Addresses.Add(new Address(baseAddress, netmask));
            }

            Log(baseAddress + " " + netmask + " added");
            return;
        }

        /// <summary>
        /// Check if an entry exists in the match list.
        /// Only entries added with <see cref="Add(string, string)"/> are considered; the match cache is not consulted.
        /// </summary>
        /// <param name="ip">The IP address, i.e. 192.168.1.0.</param>
        /// <param name="netmask">The netmask, i.e. 255.255.255.0.</param>
        /// <returns>True if entry exists.</returns>
        /// <exception cref="ArgumentNullException">Thrown when ip or netmask is null or empty.</exception>
        /// <exception cref="FormatException">Thrown when ip or netmask is not a valid IP address.</exception>
        public bool Exists(string ip, string netmask)
        {
            if (String.IsNullOrEmpty(ip)) throw new ArgumentNullException(nameof(ip));
            if (String.IsNullOrEmpty(netmask)) throw new ArgumentNullException(nameof(netmask));

            ip = IPAddress.Parse(ip).ToString();
            netmask = IPAddress.Parse(netmask).ToString();

            lock (_AddressLock)
            {
                Address curr = _Addresses.Where(d => d.Ip.Equals(ip) && d.Netmask.Equals(netmask)).FirstOrDefault();
                if (curr == default(Address))
                {
                    Log(ip + " " + netmask + " does not exist in address list");
                    return false;
                }
                else
                {
                    Log(ip + " " + netmask + " exists in address list");
                    return true;
                }
            }
        }

        /// <summary>
        /// Remove an entry from the match list.
        /// The match cache is cleared so that no address previously matched through a removed entry continues to match.
        /// </summary>
        /// <param name="ip">The IP address, i.e 192.168.1.0.</param>
        /// <exception cref="ArgumentNullException">Thrown when ip is null or empty.</exception>
        /// <exception cref="FormatException">Thrown when ip is not a valid IP address.</exception>
        public void Remove(string ip)
        {
            if (String.IsNullOrEmpty(ip)) throw new ArgumentNullException(nameof(ip));

            ip = IPAddress.Parse(ip).ToString();

            lock (_AddressLock)
            {
                _Addresses = _Addresses.Where(d => !d.Ip.Equals(ip)).ToList();
                Log(ip + " removed from address list");

                // Cleared while holding the address lock so a concurrent match cannot re-cache an address
                // through the entry being removed after the cache has been cleared.
                ClearCache();
                Log("cache cleared");
            }

            return;
        }

        /// <summary>
        /// Check if an IP address matches something in the match list.
        /// Successful subnet matches are stored in a bounded least-recently-used cache (see <see cref="CacheCapacity"/>).
        /// </summary>
        /// <param name="ip">The IP address, i.e. 192.168.1.34.</param>
        /// <returns>True if a match is found.</returns>
        /// <exception cref="ArgumentNullException">Thrown when ip is null or empty.</exception>
        /// <exception cref="FormatException">Thrown when ip is not a valid IP address.</exception>
        public bool MatchExists(string ip)
        {
            if (String.IsNullOrEmpty(ip)) throw new ArgumentNullException(nameof(ip));

            IPAddress parsed = IPAddress.Parse(ip);
            ip = parsed.ToString();

            if (CacheContains(ip))
            {
                Log(ip + " found in cache");
                return true;
            }

            lock (_AddressLock)
            {
                Address directMatch = _Addresses.Where(d => d.Ip.Equals(ip) && d.Netmask.Equals("255.255.255.255")).FirstOrDefault();
                if (directMatch != default(Address))
                {
                    Log(ip + " found in address list");
                    return true;
                }

                foreach (Address curr in _Addresses)
                {
                    if (curr.Netmask.Equals("255.255.255.255")) continue;

                    IPAddress maskedAddress;
                    if (!ApplySubnetMask(parsed, curr.ParsedNetmask, out maskedAddress)) continue;

                    if (curr.ParsedAddress.Equals(maskedAddress))
                    {
                        Log(ip + " matched from address list");
                        if (CacheAdd(ip)) Log(ip + " added to cache");
                        return true;
                    }
                }
            }

            return false;
        }

        /// <summary>
        /// Retrieve all stored addresses.
        /// </summary>
        /// <returns>List of entries in the form address/netmask.</returns>
        public List<string> All()
        {
            List<string> ret = new List<string>();

            lock (_AddressLock)
            {
                foreach (Address addr in _Addresses)
                {
                    ret.Add(addr.Ip + "/" + addr.Netmask);
                }
            }

            return ret;
        }

        /// <summary>
        /// Dispose of the matcher, releasing the match cache and its background expiration task.
        /// Matching continues to work after disposal, without caching.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        #endregion

        #region Protected-Methods

        /// <summary>
        /// Dispose of the matcher.
        /// </summary>
        /// <param name="disposing">True when called from <see cref="Dispose()"/>.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (!disposing) return;

            LRUCache<string, DateTime> previous = null;

            lock (_CacheLock)
            {
                if (_Disposed) return;
                _Disposed = true;
                previous = _Cache;
                _Cache = null;
            }

            DisposeCache(previous);
        }

        #endregion

        #region Private-Methods

        private void Log(string msg)
        {
            Logger?.Invoke(_Header + msg);
        }

        private LRUCache<string, DateTime> GetCache(bool create)
        {
            lock (_CacheLock)
            {
                if (_Cache == null && create && !_Disposed && _CacheCapacity > 0)
                {
                    // Created on first use: a matcher that never produces a subnet match never starts the cache's expiration task.
                    _Cache = new LRUCache<string, DateTime>(_CacheCapacity, Math.Max(1, _CacheCapacity / 10));
                    _Cache.Name = CacheName;
                }

                return _Cache;
            }
        }

        private bool CacheContains(string ip)
        {
            LRUCache<string, DateTime> cache = GetCache(false);
            if (cache == null) return false;

            try
            {
                return cache.TryGet(ip, out DateTime _);
            }
            catch (ObjectDisposedException)
            {
                return false;
            }
        }

        private bool CacheAdd(string ip)
        {
            LRUCache<string, DateTime> cache = GetCache(true);
            if (cache == null) return false;

            try
            {
                return cache.TryAddReplace(ip, DateTime.UtcNow);
            }
            catch (ObjectDisposedException)
            {
                return false;
            }
        }

        private void ClearCache()
        {
            LRUCache<string, DateTime> cache = GetCache(false);
            if (cache == null) return;

            try
            {
                cache.Clear();
            }
            catch (ObjectDisposedException)
            {
            }
        }

        private void DisposeCache(LRUCache<string, DateTime> cache)
        {
            if (cache == null) return;

            try
            {
                cache.Dispose();
            }
            catch (ObjectDisposedException)
            {
            }
        }

        private bool ApplySubnetMask(IPAddress address, IPAddress mask, out IPAddress masked)
        {
            masked = null;
            byte[] addrBytes = address.GetAddressBytes();
            byte[] maskBytes = mask.GetAddressBytes();

            byte[] maskedAddressBytes = null;
            if (!ApplySubnetMask(addrBytes, maskBytes, out maskedAddressBytes))
            {
                return false;
            }

            masked = new IPAddress(maskedAddressBytes);
            return true;
        }

        private bool ApplySubnetMask(byte[] value, byte[] mask, out byte[] masked)
        {
            masked = new byte[value.Length];
            for (int i = 0; i < value.Length; i++) masked[i] = 0x00;

            // Address and mask must share the same address family (i.e. byte length).
            // A cross-family comparison (e.g. an IPv6 address against an IPv4 mask) can
            // never match and must not index past the shorter array.
            if (value.Length != mask.Length) return false;

            if (!VerifyContiguousMask(mask)) return false;

            for (int i = 0; i < masked.Length; ++i)
            {
                masked[i] = (byte)(value[i] & mask[i]);
            }

            return true;
        }

        private bool VerifyContiguousMask(byte[] mask)
        {
            int i;

            // Check leading one bits 
            for (i = 0; i < mask.Length; ++i)
            {
                byte curByte = mask[i];
                if (curByte == 0xFF)
                {
                    // Full 8-bits, check next bytes. 
                }
                else if (curByte == 0)
                {
                    // A full byte of 0s. 
                    // Check subsequent bytes are all zeros. 
                    break;
                }
                else if (Array.IndexOf<byte>(_ContiguousPatterns, curByte) != -1)
                {
                    // A bit-wise contiguous ending in zeros. 
                    // Check subsequent bytes are all zeros. 
                    break;
                }
                else
                {
                    // A non-contiguous pattern -> Fail. 
                    return false;
                }
            }

            // Now check that all the subsequent bytes are all zeros. 
            for (i += 1/*next*/; i < mask.Length; ++i)
            {
                byte curByte = mask[i];
                if (curByte != 0)
                {
                    return false;
                }
            }

            return true;
        }

        private string GetBaseIpAddress(string ip, string netmask)
        {
            IPAddress ipAddr = IPAddress.Parse(ip);
            IPAddress mask = IPAddress.Parse(netmask);

            byte[] ipAddrBytes = ipAddr.GetAddressBytes();
            byte[] maskBytes = mask.GetAddressBytes();

            byte[] afterAnd = And(ipAddrBytes, maskBytes);
            IPAddress baseAddr = new IPAddress(afterAnd);
            return baseAddr.ToString();
        }

        private byte[] And(byte[] addr, byte[] mask)
        {
            if (addr.Length != mask.Length)
                throw new ArgumentException("Supplied arrays are not of the same length.");
             
            BitArray baAddr = new BitArray(addr);
            BitArray baMask = new BitArray(mask);
            BitArray baResult = baAddr.And(baMask);
            byte[] result = new byte[addr.Length];
            baResult.CopyTo(result, 0);

            /*
            Console.WriteLine("Address : " + ByteArrayToHexString(addr));
            Console.WriteLine("Netmask : " + ByteArrayToHexString(mask));
            Console.WriteLine("Result  : " + ByteArrayToHexString(result));
            */

            return result;
        }

        private byte[] ExclusiveOr(byte[] addr, byte[] mask)
        {
            if (addr.Length != mask.Length)
                throw new ArgumentException("Supplied arrays are not of the same length.");

            /*
            Console.WriteLine("Address: " + ByteArrayToHexString(addr));
            Console.WriteLine("Netmask: " + ByteArrayToHexString(mask));
            */

            byte[] result = new byte[addr.Length];

            for (int i = 0; i < addr.Length; ++i)
                result[i] = (byte)(addr[i] ^ mask[i]);

            BitArray baAddr = new BitArray(addr);
            
            return result;
        }

        private string ByteArrayToHexString(byte[] Bytes)
        {
            StringBuilder Result = new StringBuilder(Bytes.Length * 2);
            string HexAlphabet = "0123456789ABCDEF";

            foreach (byte B in Bytes)
            {
                Result.Append(HexAlphabet[(int)(B >> 4)]);
                Result.Append(HexAlphabet[(int)(B & 0xF)]);
            }

            return Result.ToString();
        }

        #endregion

        #region Private-Subordinate-Classes

        internal class Address
        {
            internal string GUID { get; set; }
            internal string Ip { get; set; }
            internal string Netmask { get; set; }
            internal IPAddress ParsedAddress { get; set; }
            internal IPAddress ParsedNetmask { get; set; }

            internal Address(string ip, string netmask)
            {
                GUID = Guid.NewGuid().ToString();
                Ip = ip;
                Netmask = netmask;
                ParsedAddress = IPAddress.Parse(ip);
                ParsedNetmask = IPAddress.Parse(netmask);
            }
        }

        #endregion
    }
}
