namespace Test.Xunit
{
    using System;
    using System.Collections.Generic;
    using System.Threading;
    using System.Threading.Tasks;

    using Test.Shared;
    using Touchstone.Core;
    using global::Xunit;

    /// <summary>
    /// Fact-style xUnit host. All shared descriptors run within a single [Fact];
    /// any failures are aggregated into one assertion failure.
    /// </summary>
    public sealed class IpMatcherFactTests
    {
        /// <summary>
        /// Run all shared descriptors as a single fact.
        /// </summary>
        [Fact]
        public async Task RunAll()
        {
            List<string> failures = new List<string>();

            foreach (TestSuiteDescriptor suite in IpMatcherSuites.All)
            {
                foreach (TestCaseDescriptor testCase in suite.Cases)
                {
                    if (testCase.Skip) continue;

                    try
                    {
                        await testCase.ExecuteAsync(CancellationToken.None);
                    }
                    catch (Exception ex)
                    {
                        failures.Add(testCase.TestId + ": " + ex.Message);
                    }
                }
            }

            if (failures.Count > 0)
                throw new TestAssertException(String.Join(Environment.NewLine, failures));
        }
    }
}
