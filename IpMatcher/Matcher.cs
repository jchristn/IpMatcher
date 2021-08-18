﻿using System;
using System.Collections;
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

        /// <summary>
        /// Method to invoke to send log messages.
        /// </summary>
        public Action<string> Logger = null;

        #endregion

        #region Private-Members

        private string _Header = "[IpMatcher] ";
        private readonly object _AddressLock = new object();
        private List<Address> _Addresses = new List<Address>();
        private readonly object _CacheLock = new object();
        private Dictionary<string, DateTime> _Cache = new Dictionary<string, DateTime>();
        private static readonly byte[] _ContiguousPatterns = { 0x80, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC, 0xFE, 0xFF };

        #endregion

        #region Constructors-and-Factories

        /// <summary>
        /// Instantiate the IP address matcher.
        /// </summary>
        public Matcher()
        { 

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

            ip = IPAddress.Parse(ip).ToString();
            netmask = IPAddress.Parse(netmask).ToString();

            string baseAddress = GetBaseIpAddress(ip, netmask);
            IPAddress parsed = IPAddress.Parse(baseAddress);
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
        /// </summary>
        /// <param name="ip">The IP address, i.e. 192.168.1.0.</param>
        /// <param name="netmask">The netmask, i.e. 255.255.255.0.</param>
        /// <returns>True if entry exists.</returns>
        public bool Exists(string ip, string netmask)
        {
            if (String.IsNullOrEmpty(ip)) throw new ArgumentNullException(nameof(ip));
            if (String.IsNullOrEmpty(netmask)) throw new ArgumentNullException(nameof(netmask));

            ip = IPAddress.Parse(ip).ToString();
            netmask = IPAddress.Parse(netmask).ToString();

            lock (_CacheLock)
            {
                if (_Cache.ContainsKey(ip))
                {
                    Log(ip + " " + netmask + " exists in cache");
                    return true;
                }
            }

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
        /// </summary>
        /// <param name="ip">The IP address, i.e 192.168.1.0.</param>
        public void Remove(string ip)
        {
            if (String.IsNullOrEmpty(ip)) throw new ArgumentNullException(nameof(ip));

            ip = IPAddress.Parse(ip).ToString();

            lock (_CacheLock)
            {
                _Cache = _Cache.Where(d => !d.Key.Equals(ip)).ToDictionary(d => d.Key, d => d.Value);
                Log(ip + " removed from cache");
            }

            lock (_AddressLock)
            {
                _Addresses = _Addresses.Where(d => !d.Ip.Equals(ip)).ToList();
                Log(ip + " removed from address list");
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

            ip = IPAddress.Parse(ip).ToString();

            IPAddress parsed = IPAddress.Parse(ip);

            lock (_CacheLock)
            {
                if (_Cache.ContainsKey(ip))
                {
                    Log(ip + " found in cache");
                    return true;
                }
            }

            List<Address> networks = new List<Address>();

            lock (_AddressLock)
            {
                Address directMatch = _Addresses.Where(d => d.Ip.Equals(ip) && d.Netmask.Equals("255.255.255.255")).FirstOrDefault();
                if (directMatch != default(Address))
                {
                    Log(ip + " found in address list");
                    return true;
                }

                networks = _Addresses.Where(d => !d.Netmask.Equals("255.255.255.255")).ToList();
            }

            if (networks.Count < 1) return false;

            foreach (Address curr in networks)
            {
                IPAddress maskedAddress;
                if (!ApplySubnetMask(parsed, curr.ParsedNetmask, out maskedAddress)) continue;

                if (curr.ParsedAddress.Equals(maskedAddress))
                {
                    Log(ip + " matched from address list");

                    lock (_CacheLock)
                    {
                        if (!_Cache.ContainsKey(ip)) _Cache.Add(ip, DateTime.Now);
                        Log(ip + " added to cache");
                    }

                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Retrieve all stored addresses.
        /// </summary>
        /// <returns></returns>
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

        #endregion

        #region Private-Methods

        private void Log(string msg)
        {
            Logger?.Invoke(_Header + msg);
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
