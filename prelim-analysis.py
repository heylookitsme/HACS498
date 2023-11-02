import requests, json
from stix2 import MemoryStore, Filter, ThreatActor

def get_data_from_branch(domain):
    """get the ATT&CK STIX data from MITRE/CTI. Domain should be 'enterprise-attack', 'mobile-attack' or 'ics-attack'. Branch should typically be master."""
    stix_json = requests.get(f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/{domain}/{domain}.json").json()
    return MemoryStore(stix_data=stix_json["objects"])

src = get_data_from_branch("enterprise-attack")

def get_group_by_alias(thesrc, alias):
    return thesrc.query([
        Filter('type', '=', 'intrusion-set'),
        Filter('aliases', '=', alias)
    ])[0]

groups = src.query([
    Filter("type", "=", "intrusion-set")
])

# get total number of groups 
print("total number of APT groups" + str(len(groups)))
print(groups[0])

for x in groups: 
    if ("goals" in x.keys()):
        print(x["name"] + "'s goals: " + x["goals"])


windows_attacks = src.query([
    Filter("type", "=", "attack-pattern"),
    Filter("x_mitre_platforms", "=", "Windows")
])

mac_attacks = src.query([
    Filter("type", "=", "attack-pattern"),
    Filter("x_mitre_platforms", "=", "macOS")
])

# get total number of windows 
print("total number of attack types on windows machines: " + str(len(windows_attacks)))
print("total number of attack types on mac machines: " + str(len(mac_attacks)))

# print(get_group_by_alias(src, 'Cozy Bear'))

indicators = src.query([
    Filter("type", "=", "campaign"),
])

print(indicators[0])

