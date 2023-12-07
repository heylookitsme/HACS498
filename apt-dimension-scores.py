# 
import requests
from stix2 import MemoryStore, Filter, ThreatActor
from stix2.utils import get_type_from_id
from pprint import pprint
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd 
from scipy.stats import zscore


def get_data_from_branch(domain):
    """get the ATT&CK STIX data from MITRE/CTI. Domain should be 'enterprise-attack', 'mobile-attack' or 'ics-attack'. Branch should typically be master."""
    stix_json = requests.get(f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/{domain}/{domain}.json").json()
    return MemoryStore(stix_data=stix_json["objects"])

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

    # See section below on "Removing revoked and deprecated objects"
    # relationships = remove_revoked_deprecated(relationships)

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

def get_techniques_by_group_software(thesrc, group_stix_id):
    # get the malware, tools that the group uses
    group_uses = [
        r for r in thesrc.relationships(group_stix_id, 'uses', source_only=True)
        if get_type_from_id(r.target_ref) in ['malware', 'tool']
    ]

    # get the technique stix ids that the malware, tools use
    software_uses = thesrc.query([
        Filter('type', '=', 'relationship'),
        Filter('relationship_type', '=', 'uses'),
        Filter('source_ref', 'in', [r.source_ref for r in group_uses])
    ])

    #get the techniques themselves
    return thesrc.query([
        Filter('type', '=', 'attack-pattern'),
        Filter('id', 'in', [r.target_ref for r in software_uses])
    ])

# software:group
def software_used_by_groups(thesrc):
    """returns group_id => {software, relationship} for each software used by the group and each software used by campaigns attributed to the group."""
    # get all software used by groups
    tools_used_by_group = get_related(thesrc, "intrusion-set", "uses", "tool")
    malware_used_by_group = get_related(thesrc, "intrusion-set", "uses", "malware")
    software_used_by_group = {**tools_used_by_group, **malware_used_by_group} # group_id -> [{software, relationship}]

    # get groups attributing to campaigns and all software used by campaigns
    software_used_by_campaign = get_related(thesrc, "campaign", "uses", "tool")
    malware_used_by_campaign = get_related(thesrc, "campaign", "uses", "malware")
    for id in malware_used_by_campaign:
        if id in software_used_by_campaign:
            software_used_by_campaign[id].extend(malware_used_by_campaign[id])
        else:
            software_used_by_campaign[id] = malware_used_by_campaign[id]
    campaigns_attributed_to_group = {
        "campaigns": get_related(thesrc, "campaign", "attributed-to", "intrusion-set", reverse=True), # group_id => {campaign, relationship}
        "software": software_used_by_campaign # campaign_id => {software, relationship}
    }

    for group_id in campaigns_attributed_to_group["campaigns"]:
        software_used_by_campaigns = []
        # check if attributed campaign is using software
        for campaign in campaigns_attributed_to_group["campaigns"][group_id]:
            campaign_id = campaign["object"]["id"]
            if campaign_id in campaigns_attributed_to_group["software"]:
                software_used_by_campaigns.extend(campaigns_attributed_to_group["software"][campaign_id])
        
        # update software used by group to include software used by a groups attributed campaign
        if group_id in software_used_by_group:
            software_used_by_group[group_id].extend(software_used_by_campaigns)
        else:
            software_used_by_group[group_id] = software_used_by_campaigns
    return software_used_by_group

def groups_using_software(thesrc):
    """returns software_id => {group, relationship} for each group using the software and each software used by attributed campaigns."""
    # get all groups using software
    groups_using_tool = get_related(thesrc, "intrusion-set", "uses", "tool", reverse=True)
    groups_using_malware = get_related(thesrc, "intrusion-set", "uses", "malware", reverse=True)
    groups_using_software = {**groups_using_tool, **groups_using_malware} # software_id => {group, relationship}

    # get campaigns attributed to groups and all campaigns using software
    campaigns_using_software = get_related(thesrc, "campaign", "uses", "tool", reverse=True)
    campaigns_using_malware = get_related(thesrc, "campaign", "uses", "malware", reverse=True)
    for id in campaigns_using_malware:
        if id in campaigns_using_software:
            campaigns_using_software[id].extend(campaigns_using_malware[id])
        else:
            campaigns_using_software[id] = campaigns_using_malware[id]
    groups_attributing_to_campaigns = {
        "campaigns": campaigns_using_software,# software_id => {campaign, relationship}
        "groups": get_related(thesrc, "campaign", "attributed-to", "intrusion-set") # campaign_id => {group, relationship}
    }

    for software_id in groups_attributing_to_campaigns["campaigns"]:
        groups_attributed_to_campaigns = []
        # check if campaign is attributed to group
        for campaign in groups_attributing_to_campaigns["campaigns"][software_id]:
            campaign_id = campaign["object"]["id"]
            if campaign_id in groups_attributing_to_campaigns["groups"]:
                groups_attributed_to_campaigns.extend(groups_attributing_to_campaigns["groups"][campaign_id])
        
        # update groups using software to include software used by a groups attributed campaign
        if software_id in groups_using_software:
            groups_using_software[software_id].extend(groups_attributed_to_campaigns)
        else:
            groups_using_software[software_id] = groups_attributed_to_campaigns
    return groups_using_software

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

def printDivider(): 
    print("-------------------------------------------------")


######################## PRELIMINARILY LOADING DATA ########################

# src = get_data_from_branch("enterprise-attack")

# using local rn because. idk bandwidth 
src = MemoryStore()
src.load_from_file("enterprise-attack.json")

# query for some basic groups of data (for convinience)
groups = src.query([Filter("type", "=", "intrusion-set")])
group_ids = [x["id"] for x in groups]

groupid_dict = dict([(gi['id'], gi['name']) for gi in groups])

campaigns = src.query([Filter("type", "=", "campaigns")])
malware = src.query([Filter("type", "=", "malware")])

# software:group
groups_using_software_map = groups_using_software(src)
# technique:group
groups_using_technique_map = groups_using_technique(src)

# map out dists. for the above 
x_axis = [x for x in groups_using_software_map] 
y_axis = [len(groups_using_software_map[x]) for x in x_axis]
group_obj = [groups_using_software_map[x] for x in x_axis]

df = pd.DataFrame({"software id":x_axis, "num groups" : y_axis, "group_obj" : group_obj})
indexEmpty = df[df["num groups"] == 0].index
df.drop(indexEmpty , inplace=True)
names = [groups_using_software_map[x][0]['object']['name'] for x in df["software id"]]
df = df.join(pd.DataFrame({"names" : names})) 

df = df.sort_values(by="num groups")
df.plot(x="software id", y="num groups", kind="bar")

plt.title('Number groups using a given software')
plt.xlabel('software')
plt.ylabel('number of groups using software')
# plt.xticks(x_axis, df["names"], rotation='vertical')
plt.gca().xaxis.set_major_locator(plt.NullLocator())
plt.show(block=False)


x_axis = [x for x in groups_using_technique_map] 
y_axis = [len(groups_using_technique_map[x]) for x in x_axis]
s = pd.DataFrame({"attack pattern id":x_axis, "num groups" : y_axis})
s = s.sort_values(by="num groups")
indexEmpty = s[s["num groups"] == 0].index
s.drop(indexEmpty , inplace=True)
names = [groups_using_software_map[x][0]['object']['name'] for x in df["software id"]]

s.plot(x="attack pattern id", y="num groups", kind="bar")
plt.title('Number of groups using a given attack pattern')
plt.xlabel('attack pattern')
plt.ylabel('number of groups using attack pattern')
plt.gca().xaxis.set_major_locator(plt.NullLocator())
plt.show(block=False)

printDivider()

# get total number of groups 
print("total number of APT groups: " + str(len(groups)))
pprint(groups[0])

printDivider()

######################## METRICS + ANALYSIS ########################

### campaigns att. to group--probably only use for distinction (like a campaign looks to be... big? so like only use for big)

def campaigns_attributed_to_group(thesrc):
    """returns group_id => {campaign, relationship} for each campaign attributed to the group."""
    return get_related(thesrc, "campaign", "attributed-to", "intrusion-set", reverse=True)

camps_att_to_group = campaigns_attributed_to_group(src)

### ------------------ softwares used for each ------------------

# alright babes, lets do number of softwares for each. ok 129 entries not bad. this is Malwares() 
#   colbalt strike is NOT a malware babes...
group_id_to_software = software_used_by_groups(src)

# todo: segement the softwares into different "kinds" of softwares 

# number of Malware() for each apt. 
groups_queried = group_id_to_software.keys()
x_axis = [x for x in groups_queried]
softwares_used_by_group = [group_id_to_software[x] for x in groups_queried]
y_axis = [len(x) for x in softwares_used_by_group]

swnum_df = pd.DataFrame({"group id":x_axis, "num tools" : y_axis})
names = [groupid_dict[x] for x in swnum_df["group id"]]
s_zscore = zscore(swnum_df["num tools"])
swnum_df = swnum_df.join(pd.DataFrame({"names" : names})) 
swnum_df = swnum_df.join(pd.DataFrame({"zscore" : s_zscore})) 
swnum_df = swnum_df.sort_values(by="num tools")
swnum_df.plot(x="names", y="num tools", kind="bar")
plt.xticks(rotation=90, fontsize=6)
plt.title('Number of Tools Used Per APT')
plt.xlabel('apt id')
plt.ylabel('number of softwares used per apt')
# plt.gca().xaxis.set_major_locator(plt.NullLocator())
plt.show(block=False)

stash = zscore(swnum_df["num tools"])

# number of APTs using malware

### ------------------ number of techniques + other analysis ------------------

# {id -> list(AttackPattern())}
listof_group_attack_patterns = [(id, get_techniques_by_group_software(src, id)) for id in group_ids]
groups_attack_patterns = dict(listof_group_attack_patterns)

# and then 1. we can graph a number 
plt.figure()
x_axis = groups_attack_patterns.keys()
y_axis = [len(groups_attack_patterns[x]) for x in groups_attack_patterns.keys()]
attack_pattern_df = pd.DataFrame({"group id":x_axis, "num attack patterns" : y_axis})
names = [groupid_dict[x] for x in attack_pattern_df["group id"]]
attack_pattern_df = attack_pattern_df.join(pd.DataFrame({"names" : names})) 

attack_pattern_df = attack_pattern_df.sort_values(by="num attack patterns")
# s.drop(indexEmpty , inplace=True)
s_zscore = zscore(attack_pattern_df["num attack patterns"])
attack_pattern_df = attack_pattern_df.join(pd.DataFrame({"zscore" : s_zscore})) 

attack_pattern_df = attack_pattern_df.sort_values(by="num attack patterns")
plt.bar(attack_pattern_df["names"], attack_pattern_df["num attack patterns"])
plt.xticks(rotation=90, fontsize=6)

plt.title('number of attack patterns per apt')
plt.xlabel('apt id')
plt.ylabel('number of attack patterns')

plt.show(block=False)

# number of APTs using attack pattern: possibly will find that mostly each APT has its own attack pattern?

### ------------------ activity & repeated success ------------------

def get_techniques_by_content(thesrc, content):
    techniques = src.query([ Filter('type', '=', 'attack-pattern') ])
    return list(filter(lambda t: content.lower() in t.description.lower(), techniques))

def get_groups_by_content(thesrc, content):
    groups = src.query([ Filter('type', '=', 'intrusion-set') ])
    print(groups[0]['description'])
    return list(filter(lambda t: content.lower() in t['description'].lower(), groups))

act = {}
for i in range(2000, 2023): 
    # TODO: SWITCH TO GET_GROUPS_BYCONTENT
    # but also it doesnt work for some reason thonking 
    act[i] = get_techniques_by_content(src, str(i))

### ------------------ NLP: analyze "danger" semantically in descriptions ------------------

# sentences similar to "attacking nation states" or like "long lasting backdoor"; 
# pick something from research that indicates what makes an apt dangerous and just look for it i guess 

########################## CHARTS !!! ##############################

final_df = attack_pattern_df.merge(swnum_df, on="group id")
final_df["composite_zscore"] = final_df["zscore_x"] + final_df["zscore_y"]
final_df.sort_values(by="composite_zscore")

# x_axis = []
# y_axis = []

# plt.bar(x_axis, y_axis)
# plt.title('number of newly reported attacks between 2018 and 2023')
# plt.xlabel('year')
# plt.ylabel('number of attacks')
# plt.show()

