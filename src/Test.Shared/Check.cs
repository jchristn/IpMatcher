namespace Test.Shared
{
    using System;
    using System.Collections.Generic;

    /// <summary>
    /// Lightweight assertion helpers used by the shared Touchstone test cases.
    /// A failed assertion throws <see cref="TestAssertException"/>, which Touchstone
    /// records as a failed test case (and which xUnit/NUnit surface as a failure).
    /// Kept framework-agnostic so Test.Shared depends only on Touchstone.Core and IpMatcher.
    /// </summary>
    public static class Check
    {
        /// <summary>
        /// Assert that a condition is true.
        /// </summary>
        /// <param name="condition">Condition expected to be true.</param>
        /// <param name="message">Message describing the expectation.</param>
        public static void True(bool condition, string message)
        {
            if (!condition) throw new TestAssertException("Expected true but was false: " + message);
        }

        /// <summary>
        /// Assert that a condition is false.
        /// </summary>
        /// <param name="condition">Condition expected to be false.</param>
        /// <param name="message">Message describing the expectation.</param>
        public static void False(bool condition, string message)
        {
            if (condition) throw new TestAssertException("Expected false but was true: " + message);
        }

        /// <summary>
        /// Assert that two values are equal using the default equality comparer.
        /// </summary>
        /// <typeparam name="T">Value type.</typeparam>
        /// <param name="expected">Expected value.</param>
        /// <param name="actual">Actual value.</param>
        /// <param name="message">Message describing the expectation.</param>
        public static void Equal<T>(T expected, T actual, string message)
        {
            if (!EqualityComparer<T>.Default.Equals(expected, actual))
                throw new TestAssertException(
                    "Expected [" + expected + "] but was [" + actual + "]: " + message);
        }

        /// <summary>
        /// Assert that invoking an action throws an exception of the specified type
        /// (or a subclass thereof).
        /// </summary>
        /// <typeparam name="TException">Expected exception type.</typeparam>
        /// <param name="action">Action expected to throw.</param>
        /// <param name="message">Message describing the expectation.</param>
        public static void Throws<TException>(Action action, string message)
            where TException : Exception
        {
            try
            {
                action();
            }
            catch (TException)
            {
                return;
            }
            catch (Exception ex)
            {
                throw new TestAssertException(
                    message + " (threw " + ex.GetType().Name + " instead of "
                    + typeof(TException).Name + ")");
            }

            throw new TestAssertException(message + " (no exception thrown)");
        }
    }

    /// <summary>
    /// Exception thrown when a shared test assertion fails.
    /// </summary>
    public sealed class TestAssertException : Exception
    {
        /// <summary>
        /// Initialize a new assertion failure.
        /// </summary>
        /// <param name="message">Description of the failed assertion.</param>
        public TestAssertException(string message) : base(message)
        {
        }
    }
}
