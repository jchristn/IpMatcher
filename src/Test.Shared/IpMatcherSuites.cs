namespace Test.Shared
{
    using System;
    using System.Collections.Generic;
    using System.Threading.Tasks;

    using global::IpMatcher;
    using Touchstone.Core;

    /// <summary>
    /// Central source of truth for all IpMatcher test cases.
    ///
    /// Every runner in the solution consumes these descriptors:
    ///   - Test.Automated (Touchstone CLI console runner)
    ///   - Test.Xunit     (Touchstone xUnit adapter)
    ///   - Test.Nunit     (Touchstone NUnit adapter)
    ///
    /// Cases exercise the full public surface of <see cref="Matcher"/>
    /// (Add, Exists, Remove, MatchExists, All, Logger, CacheCapacity, CacheCount,
    /// Dispose) across positive and
    /// negative scenarios, including argument validation, normalization,
    /// subnet-boundary behavior, cache behavior, non-contiguous masks, and IPv6.
    /// </summary>
    public static class IpMatcherSuites
    {
        /// <summary>
        /// All suites for the IpMatcher library.
        /// </summary>
        public static IReadOnlyList<TestSuiteDescriptor> All
        {
            get
            {
                return new List<TestSuiteDescriptor>
                {
                    AddSuite(),
                    ExistsSuite(),
                    RemoveSuite(),
                    MatchExistsSuite(),
                    AllSuite(),
                    LoggerSuite(),
                    IPv6Suite(),
                    CrossFamilySuite(),
                    CacheSuite(),
                };
            }
        }

        #region Suites

        /// <summary>
        /// Behavior of <see cref="Matcher.Add(string, string)"/>: normalization,
        /// idempotency, distinct masks, and argument validation.
        /// </summary>
        public static TestSuiteDescriptor AddSuite()
        {
            List<TestCaseDescriptor> cases = new List<TestCaseDescriptor>
            {
                Case("Add", "AddThenExistsBase", "Add /24 entry is retrievable via Exists", () =>
                {
                    Matcher m = new Matcher();
                    m.Add("192.168.1.0", "255.255.255.0");
                    Check.True(m.Exists("192.168.1.0", "255.255.255.0"), "added entry should exist");
                }),

                Case("Add", "HostNormalizedToBase", "Host address is normalized to its base network", () =>
                {
                    Matcher m = new Matcher();
                    m.Add("192.168.1.55", "255.255.255.0");
                    Check.True(m.Exists("192.168.1.0", "255.255.255.0"), "host normalized to base network");
                    Check.True(m.All().Contains("192.168.1.0/255.255.255.0"), "All() reflects base network");
                }),

                Case("Add", "OriginalHostFormNotStored", "Host form is not stored after normalization", () =>
                {
                    Matcher m = new Matcher();
                    m.Add("192.168.1.55", "255.255.255.0");
                    Check.False(m.Exists("192.168.1.55", "255.255.255.0"), "un-normalized host form should not exist");
                }),

                Case("Add", "DuplicateIsIdempotent", "Adding the same entry twice does not duplicate", () =>
                {
                    Matcher m = new Matcher();
                    m.Add("192.168.10.0", "255.255.255.0");
                    m.Add("192.168.10.0", "255.255.255.0");
                    Check.Equal(1, m.All().Count, "duplicate add should be idempotent");
                }),

                Case("Add", "DuplicateViaHostIsIdempotent", "Adding a host in an existing subnet is idempotent", () =>
                {
                    Matcher m = new Matcher();
                    m.Add("192.168.10.0", "255.255.255.0");
                    m.Add("192.168.10.77", "255.255.255.0");
                    Check.Equal(1, m.All().Count, "host in existing subnet should not create a new entry");
                }),

                Case("Add", "SameBaseDifferentMasksAreDistinct", "Same base with different masks are distinct entries", () =>
                {
                    Matcher m = new Matcher();
                    m.Add("10.0.0.0", "255.0.0.0");
                    m.Add("10.0.0.0", "255.255.0.0");
                    Check.Equal(2, m.All().Count, "different masks should be distinct");
                    Check.True(m.Exists("10.0.0.0", "255.0.0.0"), "/8 entry exists");
                    Check.True(m.Exists("10.0.0.0", "255.255.0.0"), "/16 entry exists");
                }),

                Case("Add", "VariousMaskWidthsStored", "Entries of /8, /16, /24, /32 are all stored", () =>
                {
                    Matcher m = new Matcher();
                    m.Add("10.0.0.0", "255.0.0.0");
                    m.Add("172.16.0.0", "255.255.0.0");
                    m.Add("192.168.1.0", "255.255.255.0");
                    m.Add("203.0.113.7", "255.255.255.255");
                    Check.Equal(4, m.All().Count, "all four widths stored");
                }),

                Case("Add", "NonContiguousMaskIsStored", "Add stores a non-contiguous mask without validating contiguity", () =>
                {
                    Matcher m = new Matcher();
                    m.Add("192.168.1.0", "255.0.255.0");
                    // 192.168.1.0 AND 255.0.255.0 => 192.0.1.0
                    Check.True(m.Exists("192.0.1.0", "255.0.255.0"), "non-contiguous entry stored at masked base");
                }),

                // Argument validation (negative)
                Case("Add", "NullIpThrows", "Add with null ip throws ArgumentNullException", () =>
                    Check.Throws<ArgumentNullException>(() => new Matcher().Add(null, "255.255.255.0"), "null ip")),

                Case("Add", "EmptyIpThrows", "Add with empty ip throws ArgumentNullException", () =>
                    Check.Throws<ArgumentNullException>(() => new Matcher().Add("", "255.255.255.0"), "empty ip")),

                Case("Add", "NullNetmaskThrows", "Add with null netmask throws ArgumentNullException", () =>
                    Check.Throws<ArgumentNullException>(() => new Matcher().Add("192.168.1.0", null), "null netmask")),

                Case("Add", "EmptyNetmaskThrows", "Add with empty netmask throws ArgumentNullException", () =>
                    Check.Throws<ArgumentNullException>(() => new Matcher().Add("192.168.1.0", ""), "empty netmask")),

                Case("Add", "InvalidIpThrows", "Add with malformed ip throws FormatException", () =>
                    Check.Throws<FormatException>(() => new Matcher().Add("not.an.ip", "255.255.255.0"), "malformed ip")),

                Case("Add", "InvalidNetmaskThrows", "Add with malformed netmask throws FormatException", () =>
                    Check.Throws<FormatException>(() => new Matcher().Add("192.168.1.0", "999.999.999.999"), "malformed netmask")),
            };

            return new TestSuiteDescriptor(
                suiteId: "Add",
                displayName: "Add - insertion, normalization, and validation",
                cases: cases);
        }

        /// <summary>
        /// Behavior of <see cref="Matcher.Exists(string, string)"/>: exact matching,
        /// normalization, isolation from the match cache, and argument validation.
        /// </summary>
        public static TestSuiteDescriptor ExistsSuite()
        {
            List<TestCaseDescriptor> cases = new List<TestCaseDescriptor>
            {
                Case("Exists", "TrueForAddedEntry", "Exists returns true for an added entry", () =>
                {
                    Matcher m = new Matcher();
                    m.Add("10.0.0.0", "255.0.0.0");
                    Check.True(m.Exists("10.0.0.0", "255.0.0.0"), "added entry exists");
                }),

                Case("Exists", "FalseForUnknownEntry", "Exists returns false for an entry never added", () =>
                {
                    Matcher m = new Matcher();
                    m.Add("192.168.1.0", "255.255.255.0");
                    Check.False(m.Exists("10.0.0.0", "255.0.0.0"), "unknown entry does not exist");
                }),

                Case("Exists", "FalseForSameIpDifferentMask", "Exists distinguishes entries by netmask", () =>
                {
                    Matcher m = new Matcher();
                    m.Add("192.168.1.0", "255.255.255.0");
                    Check.False(m.Exists("192.168.1.0", "255.255.0.0"), "same ip different mask is not the same entry");
                }),

                Case("Exists", "FalseOnEmptyMatcher", "Exists returns false on an empty matcher", () =>
                {
                    Matcher m = new Matcher();
                    Check.False(m.Exists("192.168.1.0", "255.255.255.0"), "empty matcher has no entries");
                }),

                Case("Exists", "IgnoresMatchCache", "Exists reports only added entries, never addresses held in the match cache", () =>
                {
                    Matcher m = new Matcher();
                    m.Add("192.168.5.0", "255.255.255.0");
                    Check.True(m.MatchExists("192.168.5.20"), "match populates cache");
                    Check.False(m.Exists("192.168.5.20", "255.255.255.255"), "a cached match is not an entry");
                    Check.True(m.Exists("192.168.5.0", "255.255.255.0"), "the covering entry still exists");
                }),

                // Argument validation (negative)
                Case("Exists", "NullIpThrows", "Exists with null ip throws ArgumentNullException", () =>
                    Check.Throws<ArgumentNullException>(() => new Matcher().Exists(null, "255.255.255.0"), "null ip")),

                Case("Exists", "EmptyIpThrows", "Exists with empty ip throws ArgumentNullException", () =>
                    Check.Throws<ArgumentNullException>(() => new Matcher().Exists("", "255.255.255.0"), "empty ip")),

                Case("Exists", "NullNetmaskThrows", "Exists with null netmask throws ArgumentNullException", () =>
                    Check.Throws<ArgumentNullException>(() => new Matcher().Exists("192.168.1.0", null), "null netmask")),

                Case("Exists", "EmptyNetmaskThrows", "Exists with empty netmask throws ArgumentNullException", () =>
                    Check.Throws<ArgumentNullException>(() => new Matcher().Exists("192.168.1.0", ""), "empty netmask")),

                Case("Exists", "InvalidIpThrows", "Exists with malformed ip throws FormatException", () =>
                    Check.Throws<FormatException>(() => new Matcher().Exists("300.1.1.1", "255.255.255.0"), "malformed ip")),

                Case("Exists", "InvalidNetmaskThrows", "Exists with malformed netmask throws FormatException", () =>
                    Check.Throws<FormatException>(() => new Matcher().Exists("192.168.1.0", "bad.mask"), "malformed netmask")),
            };

            return new TestSuiteDescriptor(
                suiteId: "Exists",
                displayName: "Exists - exact entry lookup and validation",
                cases: cases);
        }

        /// <summary>
        /// Behavior of <see cref="Matcher.Remove(string)"/>: removal, no-op removal,
        /// selective removal, cache interaction, and argument validation.
        /// </summary>
        public static TestSuiteDescriptor RemoveSuite()
        {
            List<TestCaseDescriptor> cases = new List<TestCaseDescriptor>
            {
                Case("Remove", "RemovesEntry", "Remove deletes the entry", () =>
                {
                    Matcher m = new Matcher();
                    m.Add("192.168.20.0", "255.255.255.0");
                    m.Remove("192.168.20.0");
                    Check.Equal(0, m.All().Count, "entry removed");
                }),

                Case("Remove", "MatchFailsAfterRemoval", "MatchExists fails after the entry is removed", () =>
                {
                    Matcher m = new Matcher();
                    m.Add("192.168.20.0", "255.255.255.0");
                    m.Remove("192.168.20.0");
                    Check.False(m.MatchExists("192.168.20.34"), "no match after removal");
                }),

                Case("Remove", "RemoveByBaseOfNormalizedEntry", "Remove uses the normalized base address", () =>
                {
                    Matcher m = new Matcher();
                    m.Add("192.168.20.55", "255.255.255.0"); // stored as base 192.168.20.0
                    m.Remove("192.168.20.0");
                    Check.Equal(0, m.All().Count, "removing the base clears the normalized entry");
                }),

                Case("Remove", "RemoveByHostFormIsNoOp", "Remove by un-normalized host form does not remove the entry", () =>
                {
                    Matcher m = new Matcher();
                    m.Add("192.168.20.55", "255.255.255.0"); // stored as base 192.168.20.0
                    m.Remove("192.168.20.55");
                    Check.Equal(1, m.All().Count, "host form does not match stored base");
                }),

                Case("Remove", "SelectiveRemoval", "Remove deletes only the matching entry", () =>
                {
                    Matcher m = new Matcher();
                    m.Add("192.168.1.0", "255.255.255.0");
                    m.Add("10.0.0.0", "255.0.0.0");
                    m.Remove("192.168.1.0");
                    Check.Equal(1, m.All().Count, "only the matching entry removed");
                    Check.True(m.Exists("10.0.0.0", "255.0.0.0"), "the other entry remains");
                }),

                Case("Remove", "RemoveNonexistentIsNoOp", "Removing a nonexistent entry is a no-op", () =>
                {
                    Matcher m = new Matcher();
                    m.Add("192.168.1.0", "255.255.255.0");
                    m.Remove("172.16.0.0");
                    Check.Equal(1, m.All().Count, "count unchanged when removing unknown ip");
                }),

                Case("Remove", "RemoveCachedHostLeavesNetwork", "Removing a cached host leaves the covering network intact", () =>
                {
                    Matcher m = new Matcher();
                    m.Add("192.168.5.0", "255.255.255.0");
                    m.MatchExists("192.168.5.20"); // caches the host address
                    m.Remove("192.168.5.20");      // no such entry; clears the cache, not the network entry
                    Check.Equal(1, m.All().Count, "network entry remains");
                    Check.True(m.MatchExists("192.168.5.20"), "host still matches via the network");
                }),

                // Argument validation (negative)
                Case("Remove", "NullIpThrows", "Remove with null ip throws ArgumentNullException", () =>
                    Check.Throws<ArgumentNullException>(() => new Matcher().Remove(null), "null ip")),

                Case("Remove", "EmptyIpThrows", "Remove with empty ip throws ArgumentNullException", () =>
                    Check.Throws<ArgumentNullException>(() => new Matcher().Remove(""), "empty ip")),

                Case("Remove", "InvalidIpThrows", "Remove with malformed ip throws FormatException", () =>
                    Check.Throws<FormatException>(() => new Matcher().Remove("nonsense"), "malformed ip")),
            };

            return new TestSuiteDescriptor(
                suiteId: "Remove",
                displayName: "Remove - deletion semantics and validation",
                cases: cases);
        }

        /// <summary>
        /// Behavior of <see cref="Matcher.MatchExists(string)"/>: subnet matching across
        /// widths, boundaries, /32 hosts, /0, non-contiguous masks, caching, and validation.
        /// </summary>
        public static TestSuiteDescriptor MatchExistsSuite()
        {
            List<TestCaseDescriptor> cases = new List<TestCaseDescriptor>
            {
                Case("MatchExists", "HostInside24", "Host inside a /24 matches", () =>
                {
                    Matcher m = new Matcher();
                    m.Add("192.168.1.0", "255.255.255.0");
                    Check.True(m.MatchExists("192.168.1.34"), "host inside /24");
                }),

                Case("MatchExists", "HostInside16", "Host inside a /16 matches", () =>
                {
                    Matcher m = new Matcher();
                    m.Add("172.16.0.0", "255.255.0.0");
                    Check.True(m.MatchExists("172.16.99.200"), "host inside /16");
                }),

                Case("MatchExists", "HostInside8", "Host inside a /8 matches", () =>
                {
                    Matcher m = new Matcher();
                    m.Add("10.0.0.0", "255.0.0.0");
                    Check.True(m.MatchExists("10.200.13.7"), "host inside /8");
                }),

                Case("MatchExists", "HostInside12", "Host inside a /12 matches at both ends", () =>
                {
                    Matcher m = new Matcher();
                    m.Add("172.16.0.0", "255.240.0.0"); // 172.16.0.0/12
                    Check.True(m.MatchExists("172.16.0.1"), "bottom of /12");
                    Check.True(m.MatchExists("172.31.255.254"), "top of /12");
                    Check.False(m.MatchExists("172.32.0.1"), "just above /12");
                    Check.False(m.MatchExists("172.15.255.255"), "just below /12");
                }),

                Case("MatchExists", "Exact32Match", "Exact /32 host matches", () =>
                {
                    Matcher m = new Matcher();
                    m.Add("172.16.5.4", "255.255.255.255");
                    Check.True(m.MatchExists("172.16.5.4"), "exact /32");
                }),

                Case("MatchExists", "Different32NoMatch", "A different /32 host does not match", () =>
                {
                    Matcher m = new Matcher();
                    m.Add("172.16.5.4", "255.255.255.255");
                    Check.False(m.MatchExists("172.16.5.5"), "different /32");
                }),

                Case("MatchExists", "NetworkAddressMatches", "The network address itself matches its subnet", () =>
                {
                    Matcher m = new Matcher();
                    m.Add("192.168.1.0", "255.255.255.0");
                    Check.True(m.MatchExists("192.168.1.0"), "network address matches");
                }),

                Case("MatchExists", "BroadcastAddressMatches", "The broadcast address matches its subnet", () =>
                {
                    Matcher m = new Matcher();
                    m.Add("192.168.1.0", "255.255.255.0");
                    Check.True(m.MatchExists("192.168.1.255"), "broadcast address matches");
                }),

                Case("MatchExists", "OutsideSubnetNoMatch", "An address outside the subnet does not match", () =>
                {
                    Matcher m = new Matcher();
                    m.Add("192.168.1.0", "255.255.255.0");
                    Check.False(m.MatchExists("192.168.2.34"), "outside /24");
                }),

                Case("MatchExists", "AdjacentAddressesNoMatch", "Addresses adjacent to the /24 boundary do not match", () =>
                {
                    Matcher m = new Matcher();
                    m.Add("192.168.1.0", "255.255.255.0");
                    Check.False(m.MatchExists("192.168.0.255"), "just below the /24");
                    Check.False(m.MatchExists("192.168.2.0"), "just above the /24");
                }),

                Case("MatchExists", "EmptyMatcherNoMatch", "An empty matcher never matches", () =>
                {
                    Matcher m = new Matcher();
                    Check.False(m.MatchExists("192.168.1.1"), "empty matcher");
                }),

                Case("MatchExists", "DefaultRouteMatchesEverything", "0.0.0.0/0 matches every address", () =>
                {
                    Matcher m = new Matcher();
                    m.Add("0.0.0.0", "0.0.0.0");
                    Check.True(m.MatchExists("8.8.8.8"), "/0 matches arbitrary address");
                    Check.True(m.MatchExists("255.255.255.255"), "/0 matches broadcast");
                    Check.True(m.MatchExists("0.0.0.0"), "/0 matches zero address");
                }),

                Case("MatchExists", "NonContiguousMaskNoMatch", "A non-contiguous netmask never produces a match", () =>
                {
                    Matcher m = new Matcher();
                    m.Add("192.168.1.0", "255.0.255.0");
                    Check.False(m.MatchExists("192.168.1.34"), "non-contiguous mask rejected");
                }),

                Case("MatchExists", "OnlyHostEntriesNoNetworkMatch", "With only /32 entries, a non-equal host does not match", () =>
                {
                    Matcher m = new Matcher();
                    m.Add("172.16.5.4", "255.255.255.255");
                    m.Add("172.16.5.6", "255.255.255.255");
                    Check.False(m.MatchExists("172.16.5.5"), "no network entries to fall back on");
                }),

                Case("MatchExists", "CachePathSecondMatch", "A repeated match is served (cache path)", () =>
                {
                    Matcher m = new Matcher();
                    m.Add("192.168.5.0", "255.255.255.0");
                    Check.True(m.MatchExists("192.168.5.20"), "first match populates cache");
                    Check.True(m.MatchExists("192.168.5.20"), "second match served from cache");
                }),

                Case("MatchExists", "MultipleEntriesEachMatch", "With multiple entries, each relevant host matches", () =>
                {
                    Matcher m = new Matcher();
                    m.Add("192.168.1.0", "255.255.255.0");
                    m.Add("10.0.0.0", "255.0.0.0");
                    m.Add("172.16.0.0", "255.255.0.0");
                    Check.True(m.MatchExists("192.168.1.9"), "matches /24");
                    Check.True(m.MatchExists("10.9.8.7"), "matches /8");
                    Check.True(m.MatchExists("172.16.1.1"), "matches /16");
                    Check.False(m.MatchExists("8.8.8.8"), "matches none");
                }),

                Case("MatchExists", "HostEntryAndNetworkEntryCoexist", "A /32 and a covering network coexist", () =>
                {
                    Matcher m = new Matcher();
                    m.Add("192.168.1.100", "255.255.255.255");
                    m.Add("192.168.1.0", "255.255.255.0");
                    Check.True(m.MatchExists("192.168.1.100"), "exact host matches");
                    Check.True(m.MatchExists("192.168.1.200"), "other host matches via network");
                }),

                // Argument validation (negative)
                Case("MatchExists", "NullIpThrows", "MatchExists with null ip throws ArgumentNullException", () =>
                    Check.Throws<ArgumentNullException>(() => new Matcher().MatchExists(null), "null ip")),

                Case("MatchExists", "EmptyIpThrows", "MatchExists with empty ip throws ArgumentNullException", () =>
                    Check.Throws<ArgumentNullException>(() => new Matcher().MatchExists(""), "empty ip")),

                Case("MatchExists", "InvalidIpThrows", "MatchExists with malformed ip throws FormatException", () =>
                    Check.Throws<FormatException>(() => new Matcher().MatchExists("300.1.1.1"), "malformed ip")),
            };

            return new TestSuiteDescriptor(
                suiteId: "MatchExists",
                displayName: "MatchExists - subnet matching, boundaries, cache, and validation",
                cases: cases);
        }

        /// <summary>
        /// Behavior of <see cref="Matcher.All"/>: emptiness, formatting, and count tracking.
        /// </summary>
        public static TestSuiteDescriptor AllSuite()
        {
            List<TestCaseDescriptor> cases = new List<TestCaseDescriptor>
            {
                Case("All", "EmptyReturnsEmptyList", "All() on an empty matcher returns an empty list", () =>
                {
                    Matcher m = new Matcher();
                    List<string> all = m.All();
                    Check.True(all != null, "All() never returns null");
                    Check.Equal(0, all.Count, "empty matcher yields empty list");
                }),

                Case("All", "FormatIsIpSlashNetmask", "All() formats entries as ip/netmask", () =>
                {
                    Matcher m = new Matcher();
                    m.Add("192.168.1.0", "255.255.255.0");
                    Check.True(m.All().Contains("192.168.1.0/255.255.255.0"), "entry formatted as ip/netmask");
                }),

                Case("All", "ReflectsMultipleEntries", "All() reflects every distinct entry", () =>
                {
                    Matcher m = new Matcher();
                    m.Add("192.168.1.0", "255.255.255.0");
                    m.Add("10.0.0.0", "255.0.0.0");
                    m.Add("172.16.0.0", "255.255.0.0");
                    Check.Equal(3, m.All().Count, "three distinct entries");
                }),

                Case("All", "TracksAddAndRemove", "All() count tracks additions and removals", () =>
                {
                    Matcher m = new Matcher();
                    m.Add("192.168.1.0", "255.255.255.0");
                    m.Add("10.0.0.0", "255.0.0.0");
                    Check.Equal(2, m.All().Count, "two after adds");
                    m.Remove("10.0.0.0");
                    Check.Equal(1, m.All().Count, "one after remove");
                }),
            };

            return new TestSuiteDescriptor(
                suiteId: "All",
                displayName: "All - enumeration and formatting",
                cases: cases);
        }

        /// <summary>
        /// Behavior of the <see cref="Matcher.Logger"/> hook.
        /// </summary>
        public static TestSuiteDescriptor LoggerSuite()
        {
            List<TestCaseDescriptor> cases = new List<TestCaseDescriptor>
            {
                Case("Logger", "InvokedOnAdd", "Logger is invoked during Add", () =>
                {
                    List<string> messages = new List<string>();
                    Matcher m = new Matcher();
                    m.Logger = s => messages.Add(s);
                    m.Add("192.168.1.0", "255.255.255.0");
                    Check.True(messages.Count > 0, "logger should receive at least one message");
                }),

                Case("Logger", "NullLoggerDoesNotThrow", "Operations work when Logger is null (default)", () =>
                {
                    Matcher m = new Matcher(); // Logger is null by default
                    m.Add("10.0.0.0", "255.0.0.0");
                    Check.True(m.MatchExists("10.1.2.3"), "operations succeed without a logger");
                }),
            };

            return new TestSuiteDescriptor(
                suiteId: "Logger",
                displayName: "Logger - optional logging hook",
                cases: cases);
        }

        /// <summary>
        /// Basic IPv6 behavior: add, exists, and prefix matching.
        /// </summary>
        public static TestSuiteDescriptor IPv6Suite()
        {
            List<TestCaseDescriptor> cases = new List<TestCaseDescriptor>
            {
                Case("IPv6", "AddAndExists", "An IPv6 prefix can be added and found via Exists", () =>
                {
                    Matcher m = new Matcher();
                    m.Add("2001:db8::", "ffff:ffff:ffff:ffff::"); // /64
                    Check.True(m.Exists("2001:db8::", "ffff:ffff:ffff:ffff::"), "IPv6 entry exists");
                }),

                Case("IPv6", "HostNormalizedToBase", "An IPv6 host address is normalized to its base prefix", () =>
                {
                    Matcher m = new Matcher();
                    m.Add("2001:db8::42", "ffff:ffff:ffff:ffff::"); // /64
                    Check.True(m.Exists("2001:db8::", "ffff:ffff:ffff:ffff::"), "IPv6 host normalized to base prefix");
                    Check.True(m.All().Contains("2001:db8::/ffff:ffff:ffff:ffff::"), "All() reflects normalized IPv6 prefix");
                }),

                Case("IPv6", "MatchInsidePrefix", "An IPv6 host inside the prefix matches", () =>
                {
                    Matcher m = new Matcher();
                    m.Add("2001:db8::", "ffff:ffff:ffff:ffff::"); // /64
                    Check.True(m.MatchExists("2001:db8::1"), "host inside IPv6 /64 matches");
                }),

                Case("IPv6", "MatchPrefixBoundaries", "IPv6 /64 prefix boundaries match and adjacent prefixes do not", () =>
                {
                    Matcher m = new Matcher();
                    m.Add("2001:db8::", "ffff:ffff:ffff:ffff::"); // /64
                    Check.True(m.MatchExists("2001:db8::"), "bottom of IPv6 /64");
                    Check.True(m.MatchExists("2001:db8::ffff:ffff:ffff:ffff"), "top of IPv6 /64");
                    Check.False(m.MatchExists("2001:db8:0:1::"), "adjacent IPv6 /64 does not match");
                }),

                Case("IPv6", "MatchOutsidePrefixNoMatch", "An IPv6 host outside the prefix does not match", () =>
                {
                    Matcher m = new Matcher();
                    m.Add("2001:db8::", "ffff:ffff:ffff:ffff::"); // /64
                    Check.False(m.MatchExists("2001:db9::1"), "host outside IPv6 /64 does not match");
                }),

                Case("IPv6", "ExactHostMatch", "An exact IPv6 /128 host matches", () =>
                {
                    Matcher m = new Matcher();
                    m.Add("2001:db8::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"); // /128
                    Check.True(m.MatchExists("2001:db8::1"), "exact IPv6 host matches");
                    Check.False(m.MatchExists("2001:db8::2"), "different IPv6 host does not match");
                }),

                Case("IPv6", "NonContiguousMaskNoMatch", "A non-contiguous IPv6 netmask never produces a match", () =>
                {
                    Matcher m = new Matcher();
                    m.Add("2001:db8::", "ffff:0:ffff::");
                    Check.False(m.MatchExists("2001:db8::1"), "non-contiguous IPv6 mask rejected");
                }),
            };

            return new TestSuiteDescriptor(
                suiteId: "IPv6",
                displayName: "IPv6 - address family support",
                cases: cases);
        }

        /// <summary>
        /// Cross-address-family behavior: an IPv4 query against an IPv6 network (and vice
        /// versa) must return a graceful "no match" rather than throwing, and entries of
        /// each family must only match hosts of the same family.
        /// </summary>
        public static TestSuiteDescriptor CrossFamilySuite()
        {
            List<TestCaseDescriptor> cases = new List<TestCaseDescriptor>
            {
                Case("CrossFamily", "IPv6QueryAgainstIPv4NetworkNoMatch", "An IPv6 host does not match an IPv4 network (and does not throw)", () =>
                {
                    Matcher m = new Matcher();
                    m.Add("10.0.0.0", "255.0.0.0"); // IPv4 /8 network
                    Check.False(m.MatchExists("2001:db8::1"), "IPv6 host must not match an IPv4 network");
                }),

                Case("CrossFamily", "IPv4QueryAgainstIPv6NetworkNoMatch", "An IPv4 host does not match an IPv6 network (and does not throw)", () =>
                {
                    Matcher m = new Matcher();
                    m.Add("2001:db8::", "ffff:ffff:ffff:ffff::"); // IPv6 /64 network
                    Check.False(m.MatchExists("192.168.1.1"), "IPv4 host must not match an IPv6 network");
                }),

                Case("CrossFamily", "IPv6QueryAgainstIPv4HostNoMatch", "An IPv6 host does not match an IPv4 /32 host entry", () =>
                {
                    Matcher m = new Matcher();
                    m.Add("203.0.113.7", "255.255.255.255"); // IPv4 /32 host
                    Check.False(m.MatchExists("2001:db8::7"), "IPv6 host must not match an IPv4 /32 entry");
                }),

                Case("CrossFamily", "AddIPv4WithIPv6MaskThrows", "Adding an IPv4 address with an IPv6 mask throws", () =>
                    Check.Throws<ArgumentException>(() => new Matcher().Add("192.168.1.0", "ffff:ffff:ffff:ffff::"), "IPv4 address with IPv6 mask")),

                Case("CrossFamily", "AddIPv6WithIPv4MaskThrows", "Adding an IPv6 address with an IPv4 mask throws", () =>
                    Check.Throws<ArgumentException>(() => new Matcher().Add("2001:db8::", "255.255.255.0"), "IPv6 address with IPv4 mask")),

                Case("CrossFamily", "ExistsWithMixedFamiliesReturnsFalse", "Exists returns false for mixed address and netmask families", () =>
                {
                    Matcher m = new Matcher();
                    m.Add("192.168.1.0", "255.255.255.0");
                    Check.False(m.Exists("192.168.1.0", "ffff:ffff:ffff:ffff::"), "IPv4 address with IPv6 netmask does not exist");
                }),

                Case("CrossFamily", "MixedFamiliesEachMatchesOwnFamily", "IPv4 and IPv6 entries coexist and each matches only its own family", () =>
                {
                    Matcher m = new Matcher();
                    m.Add("192.168.1.0", "255.255.255.0");        // IPv4 /24
                    m.Add("2001:db8::", "ffff:ffff:ffff:ffff::"); // IPv6 /64
                    Check.True(m.MatchExists("192.168.1.42"), "IPv4 host matches the IPv4 network");
                    Check.True(m.MatchExists("2001:db8::42"), "IPv6 host matches the IPv6 network");
                    Check.False(m.MatchExists("2001:db9::42"), "IPv6 host outside the IPv6 network does not match");
                    Check.False(m.MatchExists("192.168.2.42"), "IPv4 host outside the IPv4 network does not match");
                }),
            };

            return new TestSuiteDescriptor(
                suiteId: "CrossFamily",
                displayName: "CrossFamily - IPv4/IPv6 isolation and safety",
                cases: cases);
        }

        /// <summary>
        /// Behavior of the bounded match cache: capacity limit and eviction,
        /// disabling, invalidation on removal, reconfiguration, disposal, and concurrency.
        /// </summary>
        public static TestSuiteDescriptor CacheSuite()
        {
            List<TestCaseDescriptor> cases = new List<TestCaseDescriptor>
            {
                Case("Cache", "DefaultCapacity", "Default cache capacity is 4096", () =>
                {
                    using (Matcher m = new Matcher())
                    {
                        Check.Equal(4096, m.CacheCapacity, "default capacity");
                        Check.Equal(0, m.CacheCount, "cache starts empty");
                    }
                }),

                Case("Cache", "SubnetMatchIsCached", "A subnet match is stored in the cache", () =>
                {
                    using (Matcher m = new Matcher())
                    {
                        m.Add("10.0.0.0", "255.0.0.0");
                        Check.True(m.MatchExists("10.1.2.3"), "subnet match");
                        Check.Equal(1, m.CacheCount, "match cached");
                        Check.True(m.MatchExists("10.1.2.3"), "repeat match");
                        Check.Equal(1, m.CacheCount, "repeat match does not duplicate");
                    }
                }),

                Case("Cache", "MissesAndExactMatchesAreNotCached", "Misses and exact /32 matches do not populate the cache", () =>
                {
                    using (Matcher m = new Matcher())
                    {
                        m.Add("203.0.113.7", "255.255.255.255");
                        m.Add("10.0.0.0", "255.0.0.0");
                        Check.True(m.MatchExists("203.0.113.7"), "exact match");
                        Check.False(m.MatchExists("192.0.2.1"), "miss");
                        Check.Equal(0, m.CacheCount, "nothing cached");
                    }
                }),

                Case("Cache", "BoundedByCapacity", "Cache size never exceeds capacity under many distinct matches", () =>
                {
                    using (Matcher m = new Matcher(100))
                    {
                        m.Add("10.0.0.0", "255.0.0.0");
                        for (int i = 0; i < 5000; i++)
                        {
                            string ip = "10." + ((i >> 16) & 0xFF) + "." + ((i >> 8) & 0xFF) + "." + (i & 0xFF);
                            Check.True(m.MatchExists(ip), "every address in the /8 matches");
                            Check.True(m.CacheCount <= 100, "cache count within capacity");
                        }

                        Check.True(m.CacheCount > 0, "cache in use");
                        Check.True(m.MatchExists("10.0.0.1"), "evicted address still matches via the address list");
                    }
                }),

                Case("Cache", "IPv6BoundedByCapacity", "IPv6 matches are bounded by capacity", () =>
                {
                    using (Matcher m = new Matcher(10))
                    {
                        m.Add("2001:db8::", "ffff:ffff:ffff:ffff::");
                        for (int i = 1; i <= 200; i++)
                        {
                            Check.True(m.MatchExists("2001:db8::" + i.ToString("x")), "address in /64 matches");
                        }

                        Check.True(m.CacheCount <= 10, "cache count within capacity");
                    }
                }),

                Case("Cache", "ZeroCapacityDisablesCache", "Capacity 0 disables caching but matching still works", () =>
                {
                    using (Matcher m = new Matcher(0))
                    {
                        m.Add("10.0.0.0", "255.0.0.0");
                        Check.True(m.MatchExists("10.1.2.3"), "match without cache");
                        Check.True(m.MatchExists("10.1.2.3"), "repeat match without cache");
                        Check.Equal(0, m.CacheCount, "nothing cached");
                    }
                }),

                Case("Cache", "NegativeCapacityThrows", "Negative capacity throws ArgumentOutOfRangeException", () =>
                {
                    Check.Throws<ArgumentOutOfRangeException>(() => new Matcher(-1), "constructor");
                    using (Matcher m = new Matcher())
                    {
                        Check.Throws<ArgumentOutOfRangeException>(() => m.CacheCapacity = -1, "property");
                        Check.Equal(4096, m.CacheCapacity, "capacity unchanged after rejected value");
                    }
                }),

                Case("Cache", "ChangingCapacityClearsCache", "Changing capacity discards cached entries and applies the new bound", () =>
                {
                    using (Matcher m = new Matcher())
                    {
                        m.Add("10.0.0.0", "255.0.0.0");
                        for (int i = 1; i <= 50; i++) m.MatchExists("10.0.0." + i);
                        Check.Equal(50, m.CacheCount, "50 cached");
                        m.CacheCapacity = 5;
                        Check.Equal(0, m.CacheCount, "cache cleared");
                        for (int i = 1; i <= 50; i++) m.MatchExists("10.0.0." + i);
                        Check.True(m.CacheCount <= 5, "new capacity enforced");
                    }
                }),

                Case("Cache", "RemoveNetworkInvalidatesCachedHosts", "Removing a network stops previously cached hosts from matching", () =>
                {
                    using (Matcher m = new Matcher())
                    {
                        m.Add("192.168.5.0", "255.255.255.0");
                        Check.True(m.MatchExists("192.168.5.20"), "host matches and is cached");
                        m.Remove("192.168.5.0");
                        Check.Equal(0, m.CacheCount, "cache cleared on removal");
                        Check.False(m.MatchExists("192.168.5.20"), "cached host no longer matches");
                    }
                }),

                Case("Cache", "AddAfterMatchOfBaseAddress", "A cached match of a base address does not block adding a narrower entry", () =>
                {
                    using (Matcher m = new Matcher())
                    {
                        m.Add("10.0.0.0", "255.0.0.0");
                        Check.True(m.MatchExists("10.0.0.0"), "base address matches the /8 and is cached");
                        m.Add("10.0.0.0", "255.255.0.0");
                        Check.Equal(2, m.All().Count, "/16 entry added");
                        m.Remove("10.0.0.0");
                        Check.Equal(0, m.All().Count, "both entries removed");
                    }
                }),

                Case("Cache", "DisposeIsIdempotentAndMatchingContinues", "Dispose can be called repeatedly and matching still works uncached", () =>
                {
                    Matcher m = new Matcher();
                    m.Add("10.0.0.0", "255.0.0.0");
                    Check.True(m.MatchExists("10.1.2.3"), "match before dispose");
                    m.Dispose();
                    m.Dispose();
                    Check.Equal(0, m.CacheCount, "cache released");
                    Check.True(m.MatchExists("10.1.2.3"), "match after dispose");
                    Check.False(m.MatchExists("192.0.2.1"), "miss after dispose");
                    Check.Equal(0, m.CacheCount, "no cache after dispose");
                    m.Remove("10.0.0.0");
                    Check.False(m.MatchExists("10.1.2.3"), "removal after dispose");
                }),

                Case("Cache", "DisposeWithoutUse", "Disposing a matcher whose cache was never created does not throw", () =>
                {
                    Matcher m = new Matcher();
                    m.Dispose();
                    Check.Equal(0, m.CacheCount, "no cache");
                }),

                Case("Cache", "ConcurrentMatchAndRemove", "Concurrent matches, removals, and capacity changes stay bounded and do not throw", () =>
                {
                    using (Matcher m = new Matcher(64))
                    {
                        m.Add("10.0.0.0", "255.0.0.0");
                        List<Task> tasks = new List<Task>();
                        for (int t = 0; t < 8; t++)
                        {
                            int seed = t;
                            tasks.Add(Task.Run(() =>
                            {
                                for (int i = 0; i < 2000; i++)
                                {
                                    m.MatchExists("10." + seed + "." + ((i >> 8) & 0xFF) + "." + (i & 0xFF));
                                    if (i % 500 == 0) m.Remove("172.16.0.0");
                                    if (seed == 0 && i % 700 == 0) m.CacheCapacity = 64;
                                }
                            }));
                        }

                        Task.WaitAll(tasks.ToArray());
                        Check.True(m.CacheCount <= 64, "cache count within capacity");
                        Check.True(m.MatchExists("10.200.0.1"), "matching intact");
                    }
                }),

                Case("Cache", "CacheNameIsStable", "The cache telemetry name is a stable constant", () =>
                {
                    Check.Equal("ipmatcher", Matcher.CacheName, "cache name");
                }),
            };

            return new TestSuiteDescriptor(
                suiteId: "Cache",
                displayName: "Cache - bounded LRU match cache",
                cases: cases);
        }

        #endregion

        #region Helpers

        /// <summary>
        /// Wrap a synchronous test body in a Touchstone <see cref="TestCaseDescriptor"/>.
        /// </summary>
        private static TestCaseDescriptor Case(string suiteId, string caseId, string displayName, Action body)
        {
            return new TestCaseDescriptor(
                suiteId: suiteId,
                caseId: caseId,
                displayName: displayName,
                executeAsync: _ =>
                {
                    body();
                    return Task.CompletedTask;
                });
        }

        #endregion
    }
}
