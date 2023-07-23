import os
import json
import jsonschema
import subprocess
import datetime

advisories = "https://github.com/github/advisory-database"

language_map = {
    "Packagist": "php",
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

# repo = git.Repo.clone_from(advisories, f"{cwd}/advisories" )

min_schema = json.load(open("min_schema.json"))
out_file = "enriched_vuln_sources.json"

debug = False
debug_num_samples_to_resolve = 200

update_frequency_days = 7


def parse_advisory(advisory, results):
    try:
        jsonschema.validate(advisory, min_schema)
        affected = advisory["affected"][0]
        results.append({
            "language": language_map.get(affected["package"]["ecosystem"]) if affected["package"]["ecosystem"] in language_map else affected["package"]["ecosystem"],
            "vulnerable_version":  affected["ranges"][0]["events"][0]["introduced"],
            "fixed_version":  affected["ranges"][0]["events"][1]["fixed"],
            # Extracting the package type links and fixing up subpaths
            "repo": next(filter(lambda ref: ref["type"] == "PACKAGE", advisory["references"]))["url"].partition('.git')[0].partition('/tree/')[0],
            "type": advisory["database_specific"]["cwe_ids"],
            "severity": advisory["database_specific"]["severity"],
            "CVE_ID": advisory["aliases"],
            "id": advisory["id"],
            "modified": advisory["modified"]
        })
    except:
        # TODO check if any of these advisories are salvageable
        pass


def read_advisories(dir, results):
    if len(results) > debug_num_samples_to_resolve and debug:
        return
    for name in os.listdir(dir):
        path = f"{dir}/{name}"
        if os.path.isfile(path) and name.endswith("json"):
            advisory = json.load(open(path))
            parse_advisory(advisory, results)
        elif os.path.isdir(path):
            read_advisories(path, results)


def get_tag_for_version(repository, version):
    # Sometimes protocol is missing, sometimes it is http but that is recovered by the client
    if not repository.startswith("http"):
        repository = f"https://{repository}"
    # The last version that includes the version number to make sure it includes the fix already, compared to an RC
    cmd = f'git -c "versionsort.suffix=-" ls-remote --tags --sort="v:refname" {repository} | grep -F {version}  | tail -n 1 | tr -d "^{{}}" | sed "s/.*\t//g"'
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
    out = ""
    try:
        # In some cases user interaction is expected to input user/pwd; hence the timeout
        (output, err) = p.communicate(timeout=10)
        out = output.decode().strip().split('/')[-1]
    except:
        # TODO check if any of these advisories are salvageable
        pass
    return out


def get_tag_for_previous_version(repository, version):
    if not repository.startswith("http"):
        repository = f"https://{repository}"
    # First version before the version is even included in anything like RC etc
    cmd = f'git -c "versionsort.suffix=-" ls-remote --tags --sort="v:refname" {repository} | grep -F {version} -B 1 -m 1 | grep -F -v {version} | tr -d "^{{}}" | sed "s/.*\t//g"'
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
    out = ""
    try:
        (output, err) = p.communicate(timeout=10)
        out = output.decode().strip().split('/')[-1]
    except:
        # TODO check if any of these advisories are salvageable
        pass
    return out


def enrich_git_tag(vuln):
    vuln["fixed_tag"] = get_tag_for_version(
        vuln["repo"], vuln["fixed_version"])
    if vuln["vulnerable_version"] == "0":
        # If there is no specific version noted we take the version previous to the fix
        vuln["vulnerable_tag"] = get_tag_for_previous_version(
            vuln["repo"], vuln["fixed_version"])
    else:
        vuln["vulnerable_tag"] = get_tag_for_version(
            vuln["repo"], vuln["vulnerable_version"])
    if vuln["fixed_tag"] and vuln["vulnerable_tag"]:
        return vuln
    # TODO check if any of these advisories are salvageable
    return None


def create_repo_db():
    vulns = []
    # read_advisories(f"{cwd}/advisories/", vulns)
    # actually I don't think others will include any versions
    # TODO check if any of these advisories are salvageable
    read_advisories(
        f"{cwd}/advisory-database/advisories/github-reviewed", vulns)
    vulns = list(filter(lambda vuln: vuln, map(enrich_git_tag, vulns)))
    with open(out_file, "w") as f:
        json.dump(vulns, f, indent=4)


def update_repo_db():
    update_since = datetime.datetime.now() - datetime.timedelta(days=update_frequency_days)
    vulns = []
    # read_advisories(f"{cwd}/advisories/", vulns)
    # actually I don't think others will include any versions
    # TODO check if any of these advisories are salvageable
    read_advisories(
        f"{cwd}/advisory-database/advisories/github-reviewed", vulns)
    vulns = list(filter(lambda vuln: vuln,
                        map(enrich_git_tag,
                            list(filter(lambda vuln: datetime.datetime.strptime(vuln["modified"], '%Y-%m-%dT%H:%M:%SZ') > update_since, vulns)))))
    if vulns:
        print(vulns)
        vulns_old = json.load(open(out_file))
        print(map(lambda update_vuln: update_vuln["id"], vulns))
        vulns = vulns + list(filter(lambda vuln: vuln["id"] not in map(
            lambda update_vuln: update_vuln["id"], vulns), vulns_old))
        with open(out_file, "w") as f:
            json.dump(vulns, f, indent=4)
