# IpMatcher

[![NuGet Version](https://img.shields.io/nuget/v/IpMatcher.svg?style=flat)](https://www.nuget.org/packages/IpMatcher/) [![NuGet](https://img.shields.io/nuget/dt/IpMatcher.svg)](https://www.nuget.org/packages/IpMatcher) 

C# library for maintaining a match list of IP addresses and networks and comparing inputs to see if a match exists.

Effective v1.0.1, IpMatcher targets .NET Core 2.0 and .NET Framework 4.5.2.

## Help and Contribution

Please file an issue for any bugs you encounter or requested features.  Want to contribute?  Please create a branch, commit, and submit a pull request!

## Usage
```csharp
using IpMatcher;

Matcher matcher = new Matcher();
matcher.Add("192.168.1.0", "255.255.255.0");
matcher.Add("192.168.2.0", "255.255.255.0");
matcher.Remove("192.168.2.0");
matcher.Exists("192.168.1.0", "255.255.255.0");  // true
matcher.Match("192.168.1.34"); // true
matcher.Match("10.10.10.10");  // false
```

## Implementation

The matcher uses two primary internal objects.  The first is a Dictionary which acts as a faster cache.  Success responses to ```Match``` will update this Dictionary.  On ```Match``` requests, the Dictionary is checked first for a match.  Behind the Dictionary cache, a list of ```Address``` objects are stored.

## Helpful Link

A lot of the internal matching code was adapted from: https://social.msdn.microsoft.com/Forums/en-US/c0ecc0de-b45e-4ca4-8d57-fc9babd4c221/evaluate-if-ip-address-is-part-of-a-subnet?forum=netfxnetcom

## Version History

Refer to CHANGELOG.md
