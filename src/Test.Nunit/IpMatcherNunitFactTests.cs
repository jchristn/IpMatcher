namespace Test.Nunit
{
    using System.Collections.Generic;
    using System.Threading.Tasks;

    using NUnit.Framework;

    using Test.Shared;
    using Touchstone.Core;
    using Touchstone.NunitAdapter;

    /// <summary>
    /// NUnit fact-style host. All shared descriptors run within a single [Test];
    /// any failures are aggregated into one assertion failure.
    /// </summary>
    [TestFixture]
    public sealed class IpMatcherNunitFactTests : TouchstoneNunitBase
    {
        /// <inheritdoc />
        protected override IReadOnlyList<TestSuiteDescriptor> Suites
        {
            get { return IpMatcherSuites.All; }
        }

        /// <summary>
        /// Run all shared descriptors as a single test.
        /// </summary>
        [Test]
        public async Task RunAll()
        {
            await RunAllAsync();
        }
    }
}
