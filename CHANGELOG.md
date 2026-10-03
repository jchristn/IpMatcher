# Change Log

## Current Version

v1.1.0

- Bounded match cache: the unbounded Dictionary is replaced with a least-recently-used cache from the [Caching](https://www.nuget.org/packages/Caching) package (5.1.2)
- New `CacheCapacity` property and `Matcher(int cacheCapacity)` constructor (default 4096; 0 disables the cache)
- New `CacheCount` property and `Matcher.CacheName` constant (`ipmatcher`, the `cache.name` label on Caching telemetry)
- `Matcher` implements `IDisposable`. The cache is created on the first subnet match.
- Fix: `Remove` clears the match cache, so hosts matched through a removed network no longer keep matching
- Fix: `Exists` no longer reports cached match results as entries (this also stops a cached base address from blocking `Add` of a narrower entry)

## Previous Versions

v1.0.6

- Fix cross-address-family lookups (an IPv4/IPv6 mismatch returns no match instead of throwing)
- Emit symbol package (snupkg)
- Retarget to netstandard2.0, netstandard2.1, net462, net48, net8.0, net10.0

v1.0.3

- XML documentation
 
v1.0.x

- Retarget to support .NET Core 2.0 and .NET Framework 4.5.2
- Initial release