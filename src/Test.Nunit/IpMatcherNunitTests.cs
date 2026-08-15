namespace Test.Nunit
{
    using System.Collections;
    using System.Threading;
    using System.Threading.Tasks;

    using NUnit.Framework;

    using Test.Shared;
    using Touchstone.Core;
    using Touchstone.NunitAdapter;

    /// <summary>
    /// NUnit host using TestCaseSource for data-driven execution. Each non-skipped
    /// shared descriptor becomes an independent NUnit test case.
    /// </summary>
    [TestFixture]
    public sealed class IpMatcherNunitTests
    {
        private static IEnumerable TestCases()
        {
            return new TouchstoneTestCaseSource(IpMatcherSuites.All);
        }

        /// <summary>
        /// Execute a single shared test case descriptor.
        /// </summary>
        /// <param name="testCase">Test case to run.</param>
        [Test]
        [TestCaseSource(nameof(TestCases))]
        public async Task RunTest(TestCaseDescriptor testCase)
        {
            await testCase.ExecuteAsync(CancellationToken.None);
        }
    }
}
