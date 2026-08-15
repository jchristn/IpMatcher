using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using IpMatcher;

namespace Test
{
    public class Program
    {
        public static Matcher _Matcher;
        public static bool _RunForever = true;

        private static int _Passed = 0;
        private static int _Failed = 0;

        public static int Main(string[] args)
        {
            if (args != null && args.Length > 0 && args[0].Equals("interactive", StringComparison.OrdinalIgnoreCase))
            {
                Interactive();
                return 0;
            }

            return RunTests();
        }

        #region Automated-Tests

        private static int RunTests()
        {
            Console.WriteLine("Running IpMatcher tests...");
            Console.WriteLine("");

            PositiveTests();
            NegativeTests();

            Console.WriteLine("");
            Console.WriteLine("Results: " + _Passed + " passed, " + _Failed + " failed");

            return _Failed == 0 ? 0 : 1;
        }

        private static void PositiveTests()
        {
            Console.WriteLine("--- Positive test cases ---");

            // Add then MatchExists on a host within the subnet.
            {
                Matcher m = new Matcher();
                m.Add("192.168.1.0", "255.255.255.0");
                Check("Match host inside /24 subnet", m.MatchExists("192.168.1.34"));
            }

            // Add with a host address; it is normalized to the base network address.
            {
                Matcher m = new Matcher();
                m.Add("192.168.1.55", "255.255.255.0");
                Check("Host address normalized to base network", m.Exists("192.168.1.0", "255.255.255.0"));
                Check("All() reflects normalized base address",
                    m.All().Contains("192.168.1.0/255.255.255.0"));
            }

            // Exists returns true for a previously added entry.
            {
                Matcher m = new Matcher();
                m.Add("10.0.0.0", "255.0.0.0");
                Check("Exists returns true for added entry", m.Exists("10.0.0.0", "255.0.0.0"));
            }

            // Exact /32 host match.
            {
                Matcher m = new Matcher();
                m.Add("172.16.5.4", "255.255.255.255");
                Check("Exact /32 host match", m.MatchExists("172.16.5.4"));
            }

            // Larger subnet: /8 match.
            {
                Matcher m = new Matcher();
                m.Add("10.0.0.0", "255.0.0.0");
                Check("Match host inside /8 subnet", m.MatchExists("10.200.13.7"));
            }

            // /16 match.
            {
                Matcher m = new Matcher();
                m.Add("172.16.0.0", "255.255.0.0");
                Check("Match host inside /16 subnet", m.MatchExists("172.16.99.200"));
            }

            // Adding the same entry twice does not create a duplicate.
            {
                Matcher m = new Matcher();
                m.Add("192.168.10.0", "255.255.255.0");
                m.Add("192.168.10.0", "255.255.255.0");
                Check("Duplicate add is idempotent", m.All().Count == 1);
            }

            // Cache path: a second match of the same address is served from cache.
            {
                Matcher m = new Matcher();
                m.Add("192.168.5.0", "255.255.255.0");
                Check("First match populates cache", m.MatchExists("192.168.5.20"));
                Check("Second match served (cache path)", m.MatchExists("192.168.5.20"));
            }

            // Remove removes the entry.
            {
                Matcher m = new Matcher();
                m.Add("192.168.20.0", "255.255.255.0");
                m.Remove("192.168.20.0");
                Check("Remove clears the entry", m.All().Count == 0);
                Check("Match fails after removal", !m.MatchExists("192.168.20.34"));
            }

            // Multiple entries; correct one matches.
            {
                Matcher m = new Matcher();
                m.Add("192.168.1.0", "255.255.255.0");
                m.Add("10.0.0.0", "255.0.0.0");
                m.Add("172.16.0.0", "255.255.0.0");
                Check("Multiple entries - match first", m.MatchExists("192.168.1.9"));
                Check("Multiple entries - match second", m.MatchExists("10.9.8.7"));
                Check("Multiple entries - match third", m.MatchExists("172.16.1.1"));
                Check("All() returns three entries", m.All().Count == 3);
            }
        }

        private static void NegativeTests()
        {
            Console.WriteLine("");
            Console.WriteLine("--- Negative test cases ---");

            // Match against an empty matcher.
            {
                Matcher m = new Matcher();
                Check("Empty matcher does not match", !m.MatchExists("192.168.1.1"));
            }

            // Address outside the subnet does not match.
            {
                Matcher m = new Matcher();
                m.Add("192.168.1.0", "255.255.255.0");
                Check("Address outside /24 does not match", !m.MatchExists("192.168.2.34"));
            }

            // Different /32 host does not match.
            {
                Matcher m = new Matcher();
                m.Add("172.16.5.4", "255.255.255.255");
                Check("Different /32 host does not match", !m.MatchExists("172.16.5.5"));
            }

            // Exists returns false for an entry that was never added.
            {
                Matcher m = new Matcher();
                m.Add("192.168.1.0", "255.255.255.0");
                Check("Exists false for unknown entry", !m.Exists("10.0.0.0", "255.0.0.0"));
                Check("Exists false for same ip different mask",
                    !m.Exists("192.168.1.0", "255.255.0.0"));
            }

            // Non-contiguous netmask does not produce a match.
            {
                Matcher m = new Matcher();
                m.Add("192.168.1.0", "255.0.255.0");
                Check("Non-contiguous netmask does not match", !m.MatchExists("192.168.1.34"));
            }

            // Null / empty argument validation.
            CheckThrows<ArgumentNullException>("Add null ip throws", () => new Matcher().Add(null, "255.255.255.0"));
            CheckThrows<ArgumentNullException>("Add empty ip throws", () => new Matcher().Add("", "255.255.255.0"));
            CheckThrows<ArgumentNullException>("Add null netmask throws", () => new Matcher().Add("192.168.1.0", null));
            CheckThrows<ArgumentNullException>("Add empty netmask throws", () => new Matcher().Add("192.168.1.0", ""));
            CheckThrows<ArgumentNullException>("Exists null ip throws", () => new Matcher().Exists(null, "255.255.255.0"));
            CheckThrows<ArgumentNullException>("Exists null netmask throws", () => new Matcher().Exists("192.168.1.0", null));
            CheckThrows<ArgumentNullException>("Remove null ip throws", () => new Matcher().Remove(null));
            CheckThrows<ArgumentNullException>("MatchExists null ip throws", () => new Matcher().MatchExists(null));

            // Invalid IP string formatting.
            CheckThrows<FormatException>("Add invalid ip throws FormatException",
                () => new Matcher().Add("not.an.ip", "255.255.255.0"));
            CheckThrows<FormatException>("Add invalid netmask throws FormatException",
                () => new Matcher().Add("192.168.1.0", "999.999.999.999"));
            CheckThrows<FormatException>("MatchExists invalid ip throws FormatException",
                () => new Matcher().MatchExists("300.1.1.1"));
        }

        #endregion

        #region Test-Helpers

        private static void Check(string name, bool condition)
        {
            if (condition)
            {
                _Passed++;
                Console.WriteLine("  [PASS] " + name);
            }
            else
            {
                _Failed++;
                Console.WriteLine("  [FAIL] " + name);
            }
        }

        private static void CheckThrows<TException>(string name, Action action) where TException : Exception
        {
            try
            {
                action();
                _Failed++;
                Console.WriteLine("  [FAIL] " + name + " (no exception thrown)");
            }
            catch (TException)
            {
                _Passed++;
                Console.WriteLine("  [PASS] " + name);
            }
            catch (Exception e)
            {
                _Failed++;
                Console.WriteLine("  [FAIL] " + name + " (threw " + e.GetType().Name + " instead of " + typeof(TException).Name + ")");
            }
        }

        #endregion

        #region Interactive

        public static void Interactive()
        {
            _Matcher = new Matcher();
            _Matcher.Logger = Console.WriteLine;

            while (_RunForever)
            {
                Console.Write("Command [? for help] > ");
                string userInput = Console.ReadLine();
                if (String.IsNullOrEmpty(userInput)) continue;

                userInput = userInput.ToLower().Trim();

                if (userInput.Equals("?"))
                {
                    Menu();
                }
                else if (userInput.Equals("q"))
                {
                    _RunForever = false;
                }
                else if (userInput.Equals("all"))
                {
                    List<string> addresses = _Matcher.All();
                    if (addresses != null && addresses.Count > 0)
                    {
                        foreach (string addr in addresses) Console.WriteLine("  " + addr);
                    }
                    else
                    {
                        Console.WriteLine("(none)");
                    }
                }
                else if (userInput.StartsWith("add "))
                {
                    string[] addParam = userInput.Split(' ');
                    if (addParam.Length != 3) continue;
                    _Matcher.Add(addParam[1], addParam[2]);
                }
                else if (userInput.StartsWith("del "))
                {
                    string[] delParam = userInput.Split(' ');
                    if (delParam.Length != 2) continue;
                    _Matcher.Remove(delParam[1]);
                }
                else if (userInput.StartsWith("exists "))
                {
                    string[] existsParam = userInput.Split(' ');
                    if (existsParam.Length != 3) continue;
                    if (_Matcher.Exists(existsParam[1], existsParam[2]))
                    {
                        Console.WriteLine(existsParam[1] + " " + existsParam[2] + " exists");
                    }
                    else
                    {
                        Console.WriteLine(existsParam[1] + " " + existsParam[2] + " does not exist");
                    }
                }
                else if (userInput.StartsWith("match "))
                {
                    string[] matchParam = userInput.Split(' ');
                    if (matchParam.Length != 2) continue;
                    if (_Matcher.MatchExists(matchParam[1]))
                    {
                        Console.WriteLine(matchParam[1] + " matches");
                    }
                    else
                    {
                        Console.WriteLine(matchParam[1] + " does not match");
                    }
                }
                else
                {
                    continue;
                }
            }
        }

        public static void Menu()
        {
            Console.WriteLine("Commands:");
            Console.WriteLine("");
            Console.WriteLine("  all                          retrieve all stored addresses and netmasks");
            Console.WriteLine("  add <network> <netmask>      add a network to the match list");
            Console.WriteLine("                               ex: add 192.168.1.0 255.255.255.0");
            Console.WriteLine("  del <network>                remove a network from the match list");
            Console.WriteLine("                               ex: del 192.168.1.0");
            Console.WriteLine("  exists <network> <netmask>   check if network exists in match list");
            Console.WriteLine("                               ex: exists 192.168.1.0 255.255.255.0");
            Console.WriteLine("  match <address>              test if an address matches something");
            Console.WriteLine("                               ex: match 192.168.1.36");
            Console.WriteLine("");
        }

        #endregion
    }
}
