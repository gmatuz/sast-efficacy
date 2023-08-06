# sast-efficacy

Automatically updating collection of real life vulnerable code from [github advisory database](https://github.com/github/advisory-database/) basically resolving vulnerable  and fix versions to actual tags of repositories so you can check out the versions of code itself.  
Use it when you want to evaluate a SAST scanner how well it works for the languages you have and the type of vulnerabilities you expect to catch with SAST based on the CWEs.

## How to use?

Just checkout the repo and filter the `enriched_vuln_sources.json` for the languages (php, erlang, java, javascript, C#, python, flutter, ruby, rust) and CWEs something like this to look for go and C# examples of CWE-787:  
```
cat enriched_vuln_sources.json | jq -c '.[] | [select((.language=="go" or .language=="csharp") and (.type | index("CWE-787")))]'
```

## How does the version resolution work?
All resolution is looking for git tags corresponding to versions (`vulnerable_version`, `fixed_version`) in Advisory DB. The advisory DB has `vulnerable_version` in case 0 or missing it is resolved to last version before fix otherwise to the exact version in the Advisory DB; `fixed_version` is resolved to the exact version.  
Advisory DB includes package manager ecosystem which we map to corresponding languages which is conceivable to not be always accurate.
