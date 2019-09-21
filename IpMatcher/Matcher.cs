using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace IpMatcher
{
    /// <summary>
    /// IP address matcher.
    /// </summary>
    public class Matcher
    {
        #region Public-Members

        #endregion

        #region Private-Members

        private readonly object _AddressLock;
        private List<Address> _Addresses;

        private readonly object _CacheLock;
        private Dictionary<string, DateTime> _Cache;

        private static readonly byte[] _ContiguousPatterns = { 0x80, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC, 0xFE, 0xFF };

        #endregion

        #region Constructors-and-Factories

        /// <summary>
        /// Instantiate the IP address matcher.
        /// </summary>
        public Matcher()
        {
            _AddressLock = new object();
            _Addresses = new List<Address>();
            _CacheLock = new object();
            _Cache = new Dictionary<string, DateTime>();
        }

        #endregion

        #region Public-Methods

        /// <summary>
        /// Add a node to the match list.
        /// </summary>
        /// <param name="ip">The IP address, i.e. 192.168.1.0.</param>
        /// <param name="netmask">The netmask, i.e. 255.255.255.0.</param>
        public void Add(string ip, string netmask)
        {
            if (String.IsNullOrEmpty(ip)) throw new ArgumentNullException(nameof(ip));
            if (String.IsNullOrEmpty(netmask)) throw new ArgumentNullException(nameof(netmask));

            IPAddress parsed = IPAddress.Parse(ip); // just to create exception
            if (Exists(ip, netmask)) return;

            lock (_AddressLock)
            {
                _Addresses.Add(new Address(ip, netmask));
            }

            Debug.WriteLine(ip + " " + netmask + " added");
            return;
        }

        /// <summary>
        /// Check if an entry exists in the match list.
        /// </summary>
        /// <param name="ip">The IP address, i.e. 192.168.1.0.</param>
        /// <param name="netmask">The netmask, i.e. 255.255.255.0.</param>
        /// <returns>True if entry exists.</returns>
        public bool Exists(string ip, string netmask)
        {
            if (String.IsNullOrEmpty(ip)) throw new ArgumentNullException(nameof(ip));
            if (String.IsNullOrEmpty(netmask)) throw new ArgumentNullException(nameof(netmask));

            lock (_CacheLock)
            {
                if (_Cache.ContainsKey(ip))
                {
                    Debug.WriteLine(ip + " " + netmask + " exists in cache");
                    return true;
                }
            }

            lock (_AddressLock)
            {
                Address curr = _Addresses.Where(d => d.Ip.Equals(ip) && d.Netmask.Equals(netmask)).FirstOrDefault();
                if (curr == default(Address))
                {
                    Debug.WriteLine(ip + " " + netmask + " does not exist in address list");
                    return false;
                }
                else
                {
                    Debug.WriteLine(ip + " " + netmask + " exists in address list");
                    return true;
                }
            }
        }

        /// <summary>
        /// Remove an entry from the match list.
        /// </summary>
        /// <param name="ip">The IP address, i.e 192.168.1.0.</param>
        public void Remove(string ip)
        {
            if (String.IsNullOrEmpty(ip)) throw new ArgumentNullException(nameof(ip));

            lock (_CacheLock)
            {
                _Cache = _Cache.Where(d => !d.Key.Equals(ip)).ToDictionary(d => d.Key, d => d.Value);
                Debug.WriteLine(ip + " removed from cache");
            }

            lock (_AddressLock)
            {
                _Addresses = _Addresses.Where(d => !d.Ip.Equals(ip)).ToList();
                Debug.WriteLine(ip + " removed from address list");
            }

            return;
        }

        /// <summary>
        /// Check if an IP address matches something in the match list.
        /// </summary>
        /// <param name="ip">The IP address, i.e. 192.168.1.34.</param>
        /// <returns>True if a match is found.</returns>
        public bool MatchExists(string ip)
        {
            if (String.IsNullOrEmpty(ip)) throw new ArgumentNullException(nameof(ip));

            IPAddress parsed = IPAddress.Parse(ip);

            lock (_CacheLock)
            {
                if (_Cache.ContainsKey(ip))
                {
                    Debug.WriteLine(ip + " found in cache");
                    return true;
                }
            }

            List<Address> networks = new List<Address>();

            lock (_AddressLock)
            {
                Address directMatch = _Addresses.Where(d => d.Ip.Equals(ip) && d.Netmask.Equals("255.255.255.255")).FirstOrDefault();
                if (directMatch != default(Address))
                {
                    Debug.WriteLine(ip + " found in address list");
                    return true;
                }

                networks = _Addresses.Where(d => !d.Netmask.Equals("255.255.255.255")).ToList();
            }

            if (networks.Count < 1) return false;

            foreach (Address curr in networks)
            {
                IPAddress maskedAddress;
                if (!ApplySubnetMask(parsed, curr.ParsedNetmask, out maskedAddress))
                {
                    continue;
                }

                if (curr.ParsedAddress.Equals(maskedAddress))
                {
                    Debug.WriteLine(ip + " matched from address list");

                    lock (_CacheLock)
                    {
                        if (!_Cache.ContainsKey(ip)) _Cache.Add(ip, DateTime.Now);
                        Debug.WriteLine(ip + " added to cache");
                    }

                    return true;
                }
            }

            return false;
        }

        #endregion

        #region Private-Methods

        private static bool ApplySubnetMask(IPAddress address, IPAddress mask, out IPAddress masked)
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

        private static bool ApplySubnetMask(byte[] value, byte[] mask, out byte[] masked)
        {
            masked = new byte[value.Length];
            for (int i = 0; i < value.Length; i++) masked[i] = 0x00;

            if (!VerifyContiguousMask(mask)) return false;

            for (int i = 0; i < masked.Length; ++i)
            {
                masked[i] = (byte)(value[i] & mask[i]);
            }

            return true;
        }

        private static bool VerifyContiguousMask(byte[] mask)
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

        #endregion

        #region Private-Subordinate-Classes

        internal class Address
        {
            public string GUID { get; set; }
            public string Ip { get; set; }
            public string Netmask { get; set; }
            public IPAddress ParsedAddress { get; set; }
            public IPAddress ParsedNetmask { get; set; }

            public Address(string ip, string netmask)
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
