import os
import json
import jsonschema
import subprocess

advisories = "https://github.com/github/advisory-database"

language_map = {
  "Packagist" : "php",
  "Erlang": "erlang",
  "Go": "go",
  "Maven": "java",
  "npm": "javascript",
  "NuGet": "csharp",
  "PyPI": "python",
  "Pub": "flutter",
  "RubyGems": "ruby",
  "rust": "rust",
  "crates.io": "rust"
}

cwd = os.getcwd()

#repo = git.Repo.clone_from(advisories, f"{cwd}/advisories" )

min_schema = json.load(open("min_schema.json"))

num_samples_to_resolve = 20

def read_advisories(dir, results):
    if len(results) > 15:
        return
    for name in os.listdir(dir):
        path = f"{dir}/{name}"
        if os.path.isfile(path) and name.endswith("json"):
            advisory = json.load(open(path))
            try:
                jsonschema.validate(advisory, min_schema)
                affected = advisory["affected"][0]
                results.append({
                    "language": language_map.get(affected["package"]["ecosystem"]) if affected["package"]["ecosystem"] in language_map else affected["package"]["ecosystem"],
                    "vulnerable_version":  affected["ranges"][0]["events"][0]["introduced"],
                    "fixed_version":  affected["ranges"][0]["events"][1]["fixed"],
                    "repo": next(filter(lambda ref: ref["type"] == "PACKAGE", advisory["references"])),
                    "type": advisory["database_specific"]["cwe_ids"],
                    "severity": advisory["database_specific"]["severity"],
                    "CVE_ID": advisory["aliases"]
                })
            except:
                pass
        elif os.path.isdir(path):
            read_advisories(path, results)

def get_tag_for_version(repository, version):
    if not repository.startswith("https://"):
        repository = f"https://{repository}"
    #The last version that includes the version number to make sure it includes the fix already, compared to an RC
    cmd = f'timeout 10 git -c "versionsort.suffix=-" ls-remote --tags --sort="v:refname" {repository} | grep -F {version}  | tail -n 1 | tr -d "^{{}}" | sed "s/.*\t//g"'
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
    (output, err) = p.communicate()
    out = output.decode()
    return out.strip().split('/')[-1]

def get_tag_for_previous_version(repository, version):
    if not repository.startswith("https://"):
        repository = f"https://{repository}"
    #First version before the version is even included in anything like RC etc
    cmd = f'timeout 10 git -c "versionsort.suffix=-" ls-remote --tags --sort="v:refname" {repository} | grep -F {version} -B 1 -m 1 | grep -F -v {version} | tr -d "^{{}}" | sed "s/.*\t//g"'
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
    (output, err) = p.communicate()
    out = output.decode()
    return out.strip().split('/')[-1]

def enrich_git_tag(vuln):
    vuln["fixed_tag"] = get_tag_for_version(vuln["repo"]["url"], vuln["fixed_version"])
    if vuln["vulnerable_version"] == "0":
        #If there is no specific version noted we take the version previous to the fix
        vuln["vulnerable_tag"] = get_tag_for_previous_version(vuln["repo"]["url"], vuln["fixed_version"])
    else:
        vuln["vulnerable_tag"] = get_tag_for_version(vuln["repo"]["url"], vuln["vulnerable_version"])
    if vuln["fixed_tag"] and vuln["vulnerable_tag"]:
        return vuln
    return None

#def enrich_git_tags(vulns):
#    for vuln in vulns:
        #TODO: sometime https:// is missing from the repo name
#        if vuln["vulnerable_version"] == "0":
#            vuln["vulnerable_tag"] = find_previous_verions_tag(vuln["repo"]["url"], vuln["fixed_version"])
#            vuln["fixed_tag"] = get_tag_for_version(vuln["repo"]["url"], vuln["fixed_version"])
#        else:
#            vuln["fixed_tag"] = get_tag_for_version(vuln["repo"]["url"], vuln["fixed_version"])
#            vuln["vulnerable_tag"] = get_tag_for_version(vuln["repo"]["url"], vuln["vulnerable_version"])
#        if vuln["fixed_tag"] and vuln["vulnerable_tag"]:
#            repoed.append(vuln)

def create_repo_db():
    vulns = []
    #read_advisories(f"{cwd}/advisories/", vulns)
    #actually I don't think others will include any versions
    read_advisories(f"{cwd}/advisories/advisories/github-reviewed", vulns)
    vulns = list(map(enrich_git_tag, vulns))
    with open("enriched_vuln_sources.json", "w") as f:
        json.dump(vulns,f)

create_repo_db()