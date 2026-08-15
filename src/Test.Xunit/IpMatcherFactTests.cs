namespace Test.Xunit
{
    using System.Collections.Generic;
    using System.Threading.Tasks;

    using Test.Shared;
    using Touchstone.Core;
    using Touchstone.XunitAdapter;
    using global::Xunit;

    /// <summary>
    /// Fact-style xUnit host. All shared descriptors run within a single [Fact];
    /// any failures are aggregated into one assertion failure.
    /// </summary>
    public sealed class IpMatcherFactTests : TouchstoneFactBase
    {
        /// <inheritdoc />
        protected override IReadOnlyList<TestSuiteDescriptor> Suites
        {
            get { return IpMatcherSuites.All; }
        }

        /// <summary>
        /// Run all shared descriptors as a single fact.
        /// </summary>
        [Fact]
        public async Task RunAll()
        {
            await RunAllAsync();
        }
    }
}
