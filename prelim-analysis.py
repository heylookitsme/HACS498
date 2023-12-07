import requests, json
from stix2 import MemoryStore, Filter, ThreatActor
import matplotlib.pyplot as plt
import numpy as np


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

##########################

from stix2 import Filter

def get_created_after(thesrc, timestamp):
    filt = [
        Filter('created', '>', timestamp)
    ]
    return thesrc.query(filt)

most_common = ['colbalt strike', 'lazarus group', 'kimsuky', 'magic hound', 'apt32', 'apt28', 'empire', 'invisbole', 'sandworm team', 'qakbot']

print("AFTERAFTERAFTER")

# recent_attacks = src.query([
#     Filter("type", "=", "attack-pattern"),
#     Filter('created', '>', "2020-10-01T00:14:20.652Z")
# ])

# print(recent_attacks[0])

x_axis = []
y_axis = []

for x in range(2018, 2023): 
    # print(x) 
    recent_attacks = src.query([
        Filter("type", "=", "attack-pattern"),
        Filter('created', '>', str(x) + "-10-01T00:14:20.652Z"),
        Filter('created', '<', str(x + 1) + "-10-01T00:14:20.652Z"),
        # Filter('kill_chain_phases.phase_name', '=', "defense-evasion"),
        # Filter('kill_chain_phases.kill_chain_name', '=', 'mitre-attack'),
    ])
    # print(len(recent_attacks))
    x_axis.append(x)
    y_axis.append(len(recent_attacks))


plt.bar(x_axis, y_axis)
plt.title('number of newly reported attacks between 2018 and 2023')
plt.xlabel('year')
plt.ylabel('number of attacks')
plt.show()


###############################################



weight_counts = {
    "Below": np.array([70, 31, 58]),
    "Above": np.array([82, 37, 66]),
}

species = (
    "Adelie\n $\\mu=$3700.66g",
    "Chinstrap\n $\\mu=$3733.09g",
    "Gentoo\n $\\mu=5076.02g$",
)


def get_related(thesrc, src_type, rel_type, target_type, reverse=False):
    """build relationship mappings
       params:
         thesrc: MemoryStore to build relationship lookups for
         src_type: source type for the relationships, e.g "attack-pattern"
         rel_type: relationship type for the relationships, e.g "uses"
         target_type: target type for the relationship, e.g "intrusion-set"
         reverse: build reverse mapping of target to source
    """

    relationships = thesrc.query([
        Filter('type', '=', 'relationship'),
        Filter('relationship_type', '=', rel_type),
        Filter('revoked', '=', False),
    ])

    # stix_id => [ { relationship, related_object_id } for each related object ]
    id_to_related = {}

    # build the dict
    for relationship in relationships:
        if src_type in relationship.source_ref and target_type in relationship.target_ref:
            if (relationship.source_ref in id_to_related and not reverse) or (relationship.target_ref in id_to_related and reverse):
                # append to existing entry
                if not reverse:
                    id_to_related[relationship.source_ref].append({
                        "relationship": relationship,
                        "id": relationship.target_ref
                    })
                else:
                    id_to_related[relationship.target_ref].append({
                        "relationship": relationship,
                        "id": relationship.source_ref
                    })
            else:
                # create a new entry
                if not reverse:
                    id_to_related[relationship.source_ref] = [{
                        "relationship": relationship,
                        "id": relationship.target_ref
                    }]
                else:
                    id_to_related[relationship.target_ref] = [{
                        "relationship": relationship,
                        "id": relationship.source_ref
                    }]
    # all objects of relevant type
    if not reverse:
        targets = thesrc.query([
            Filter('type', '=', target_type),
            Filter('revoked', '=', False)
        ])
    else:
        targets = thesrc.query([
            Filter('type', '=', src_type),
            Filter('revoked', '=', False)
        ])

    # build lookup of stixID to stix object
    id_to_target = {}
    for target in targets:
        id_to_target[target.id] = target

    # build final output mappings
    output = {}
    for stix_id in id_to_related:
        value = []
        for related in id_to_related[stix_id]:
            if not related["id"] in id_to_target:
                continue  # targeting a revoked object
            value.append({
                "object": id_to_target[related["id"]],
                "relationship": related["relationship"]
            })
        output[stix_id] = value
    return output

def groups_using_technique(thesrc):
    """returns technique_id => {group, relationship} for each group using the technique and each campaign attributed to groups using the technique."""
    # get all groups using techniques
    groups_using_techniques = get_related(thesrc, "intrusion-set", "uses", "attack-pattern", reverse=True) # technique_id => {group, relationship}

    # get campaigns attributed to groups and all campaigns using techniques
    groups_attributing_to_campaigns = {
        "campaigns": get_related(thesrc, "campaign", "uses", "attack-pattern", reverse=True), # technique_id => {campaign, relationship}
        "groups": get_related(thesrc, "campaign", "attributed-to", "intrusion-set") # campaign_id => {group, relationship}
    }

    for technique_id in groups_attributing_to_campaigns["campaigns"]:
        campaigns_attributed_to_group = []
        # check if campaign is attributed to group
        for campaign in groups_attributing_to_campaigns["campaigns"][technique_id]:
            campaign_id = campaign["object"]["id"]
            if campaign_id in groups_attributing_to_campaigns["groups"]:
                campaigns_attributed_to_group.extend(groups_attributing_to_campaigns["groups"][campaign_id])
        
        # update groups using techniques to include techniques used by a groups attributed campaign
        if technique_id in groups_using_techniques:
            groups_using_techniques[technique_id].extend(campaigns_attributed_to_group)
        else:
            groups_using_techniques[technique_id] = campaigns_attributed_to_group
    return groups_using_techniques

a = groups_using_technique(src)
print(len(a))

for x in range(2018, 2023): 
    # print(x) 
    recent_attacks = src.query([
        Filter("type", "=", "attack-pattern"),
        Filter('created', '>', str(x) + "-10-01T00:14:20.652Z"),
        Filter('created', '<', str(x + 1) + "-10-01T00:14:20.652Z"),
        # Filter('kill_chain_phases.phase_name', '=', "defense-evasion"),
        # Filter('kill_chain_phases.kill_chain_name', '=', 'mitre-attack'),
    ])

        
    # print(len(recent_attacks))
    x_axis.append(x)
    y_axis.append(len(recent_attacks))

fig, ax = plt.subplots()
bottom = np.zeros(3)
width = 0.5

for boolean, weight_count in weight_counts.items():
    p = ax.bar(species, weight_count, width, label=boolean, bottom=bottom)
    bottom += weight_count

plt.show()