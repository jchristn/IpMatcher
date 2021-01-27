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

        public static void Main(string[] args)
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
    }
}
