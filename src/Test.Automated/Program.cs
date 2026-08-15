using System.Threading.Tasks;

using Test.Shared;
using Touchstone.Cli;

// Touchstone CLI runner over the shared IpMatcher suites (the central source of truth).
//   dotnet run                      -> run all suites, exit 0 on success / 1 on failure
//   dotnet run -- --results out.json -> also export machine-readable results to out.json
string resultsPath = null;

for (int i = 0; i < args.Length; i++)
{
    if (args[i] == "--results" && i + 1 < args.Length)
    {
        resultsPath = args[i + 1];
        break;
    }
}

return await ConsoleRunner.RunAsync(IpMatcherSuites.All, resultsPath: resultsPath);
