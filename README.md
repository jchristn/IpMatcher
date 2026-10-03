# IpMatcher

[![NuGet Version](https://img.shields.io/nuget/v/IpMatcher.svg?style=flat)](https://www.nuget.org/packages/IpMatcher/) [![NuGet](https://img.shields.io/nuget/dt/IpMatcher.svg)](https://www.nuget.org/packages/IpMatcher) 

C# library for maintaining a match list of IP addresses and networks and comparing inputs to see if a match exists.

IpMatcher targets .NET Standard 2.0 and 2.1, .NET Framework 4.6.2 and 4.8, and .NET 8 and 10.

## Help and Contribution

Please file an issue for any bugs you encounter or requested features.  Want to contribute?  Please create a branch, commit, and submit a pull request!

## Usage
```csharp
using IpMatcher;

using (Matcher matcher = new Matcher())
{
    matcher.Add("192.168.1.0", "255.255.255.0");
    matcher.Add("192.168.2.0", "255.255.255.0");
    matcher.Remove("192.168.2.0");
    matcher.Exists("192.168.1.0", "255.255.255.0");  // true
    matcher.MatchExists("192.168.1.34"); // true
    matcher.MatchExists("10.10.10.10");  // false
}
```

`Matcher` implements `IDisposable`. Dispose it when you are done with it to release the match cache and the cache's background expiration task.

## Implementation

The matcher uses two primary internal objects.  The first is a bounded least-recently-used cache (from the [Caching](https://www.nuget.org/packages/Caching) package) of IP addresses that previously matched a network entry.  Subnet matches found by ```MatchExists``` are added to this cache, and ```MatchExists``` checks it first.  Behind the cache, a list of ```Address``` objects are stored.

The cache holds at most ```CacheCapacity``` addresses (default 4096), so memory stays bounded no matter how many distinct addresses are matched.  When it fills, the least recently used addresses are evicted; an evicted address still matches through the address list.

```csharp
Matcher matcher = new Matcher(cacheCapacity: 10000); // or set matcher.CacheCapacity later
matcher.CacheCapacity = 0;                            // disable the cache entirely
int cached = matcher.CacheCount;                      // addresses currently cached
```

- The cache is created on the first subnet match, so a matcher that is empty or holds only /32 entries never starts the cache's background expiration task.
- ```Remove``` clears the cache, so an address matched through a removed network stops matching right away.
- ```Exists``` only checks added entries, not the cache.
- Changing ```CacheCapacity``` discards the cached entries.

### Telemetry

IpMatcher does not emit telemetry itself.  The match cache is named ```ipmatcher``` (```Matcher.CacheName```), so if your host subscribes to the Caching library's ```Caching``` meter and activity source, cache size, hit/miss, and eviction metrics are reported with ```cache.name="ipmatcher"```.

## Helpful Link

A lot of the internal matching code was adapted from: https://social.msdn.microsoft.com/Forums/en-US/c0ecc0de-b45e-4ca4-8d57-fc9babd4c221/evaluate-if-ip-address-is-part-of-a-subnet?forum=netfxnetcom

## Version History

Refer to CHANGELOG.md
