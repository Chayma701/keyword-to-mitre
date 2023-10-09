import re
import time

import openpyxl
import requests
from bs4 import BeautifulSoup
from mitreattack.stix20 import MitreAttackData
from stix2 import FileSystemSource, Filter

mitre_ent = MitreAttackData('MITRE/enterprise-attack.json')
mitre_mobile = MitreAttackData('MITRE/mobile-attack.json')
mitre_ics = MitreAttackData('MITRE/ics-attack.json')

fs = FileSystemSource('./CAPEC/2.1', allow_custom=True)

api_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId='
url = 'https://www.fortiguard.com/search?q='
api_key = #add_api_key

headers = {
    'apiKey': api_key  # Use the header key specified by the API
}

# Create a new Excel workbook and select the active sheet
workbook = openpyxl.Workbook()
sheet = workbook.active
sheet.append(['Attack', 'CVE', 'CWE', 'CAPEC', 'Technique', 'Tactic'])


def get_object_by_attack_id(attack_id, stix_type):
    return mitre_ent.get_object_by_attack_id(attack_id, stix_type)


def get_objects_by_name(name, stix_type):
    return mitre_ent.get_objects_by_name(name, stix_type)


def get_technique_by_capec_id(capec_id):
    filter = [
        Filter('external_references.external_id', '=', capec_id),
        Filter('type', '=', 'attack-pattern')
    ]
    techniques = []
    for item in fs.query(filter):
        for external_refrence in item['external_references']:
            if external_refrence['source_name'] == 'ATTACK':
                techniques.append(external_refrence['external_id'])
    return techniques


def get_capec_id_by_cwe(cwe):
    filter = [
        Filter('external_references.external_id', '=', cwe),
        Filter('type', '=', 'attack-pattern')
    ]
    return [capec['external_references'][0]['external_id'] for capec in fs.query(filter)]


def get_all_parents_by_capec_id(capec_id):
    if ':' in capec_id:
        capec_id = capec_id
    parents = []
    # Assuming you have a function to query data based on capec_id, replace this with your actual implementation
    filter = [
        Filter('external_references.external_id', '=', capec_id),
        Filter('type', '=', 'attack-pattern')
    ]
    ap_data = fs.query(filter)
    if ap_data:
        if 'x_capec_child_of_refs' in ap_data[0]:
            for parent in ap_data[0]['x_capec_child_of_refs']:
                parent_data = get_capec_id_by_attack_pattern(parent)
                parents.append(parent_data)
                # Recursively call the function to handle parent's techniques
                technique_data = get_all_parents_by_capec_id(parent_data)
                parents.extend(technique_data)

    return parents

def get_all_techniques_by_capec_id(capec_id):
    all_parents = get_all_parents_by_capec_id(capec_id)
    all_techniques = []
    for parent in all_parents:
        all_techniques.extend(get_technique_by_capec_id(parent))
    return all_techniques



def get_capec_id_by_attack_pattern(ap_stix_id):
    ap = fs.get(ap_stix_id)
    if 'external_references' in ap:
        for external_reference in ap['external_references']:
            if external_reference['source_name'] == 'capec':
                return external_reference['external_id'] + ': ' + ap['name']
    return ''

def get_tactic_info(tactic_name):
    data = get_objects_by_name(tactic_name, 'x-mitre-tactic')
    if len(data) > 0:
        data = data[0]
        return data['external_references'][0]['external_id'] + ': ' + tactic_name
    else:
        return 'N/A'

def flatten_list(nested_list):
    result = []
    for item in nested_list:
        if isinstance(item, list):
            result.extend(flatten_list(item))
        else:
            result.append(item)
    return result

def get_mapping_by_cwe_id(cwe_id):
    print("looking for CWE: ", cwe_id, "...")
    capecs = get_capec_id_by_cwe(cwe_id)
    cwe_link = '=HYPERLINK("https://cwe.mitre.org/data/definitions/' + cwe_id.split('-')[
        1] + '.html","' + cwe_id + '")'
    if len(capecs) == 0:
        print('No CAPECs found for CWE: ', cwe_id, "...adding empty row")
        return ['', '', cwe_link, 'N/A', 'N/A', 'N/A']
    data = []
    for capec in capecs:
        capec_link = '=HYPERLINK("https://capec.mitre.org/data/definitions/' + capec.split('-')[
            1] + '.html","' + capec + '")'
        teq_ids = get_technique_by_capec_id(capec)
        parent_techniques = get_all_techniques_by_capec_id(capec)
        if parent_techniques:
            teq_ids.append(parent_techniques)
            teq_ids = flatten_list(teq_ids)
        if len(teq_ids) == 0:
            print('No techniques found for CAPEC: ', capec, "...adding empty row")
            data.append(['', '', cwe_link, capec_link, 'N/A', 'N/A'])
        for teq_id in teq_ids:
            teq = get_object_by_attack_id(teq_id, 'attack-pattern')
            teq_name = teq['name']
            for tactic in teq['kill_chain_phases']:
                tactic_info = '=HYPERLINK("https://attack.mitre.org/tactics/' + tactic['phase_name'].replace('-', ' ').title() + '","' + get_tactic_info(tactic['phase_name'].replace('-', ' ').title()) + '")'
                teq_info = '=HYPERLINK("https://attack.mitre.org/techniques/' + teq_id + '","' + teq_id + ': ' + teq_name + '")'
                print("adding row: ", [cwe_id, capec, teq_info, tactic_info])
                data.append(['', '', cwe_link, capec_link, teq_info, tactic_info])
    return data



def get_weakness_by_cve_id(cve_id):
    response = requests.get(api_url + cve_id, headers=headers)
    if response.status_code == 200:
        data = response.json()
        if data['totalResults'] == 0:
            return None
        if 'weaknesses' not in data['vulnerabilities'][0]['cve']:
            return None
        return [weakness['description'][0]['value'] for weakness in data['vulnerabilities'][0]['cve']['weaknesses']]
    else:
        print("Error: ", response.status_code)
        return None


def add_rest_of_row(cve_id):
    cwes = get_weakness_by_cve_id(cve_id)
    print("rest of row: ", cwes, "...")
    if cwes is None:
        return []
    cwes = list(set(get_weakness_by_cve_id(cve_id)))
    return [get_mapping_by_cwe_id(cwe) for cwe in cwes]


with open('list1_attack.txt', 'r') as f:
    next(f)  # Skip the first line
    for line in f:
        attack = line.split('=')[1].replace('"', '').replace('\n', '')  # Extract the attack name
        print("looking for CVEs for: ", attack, "...")
        print("visiting: ", url + attack, "...")
        response = requests.get(url + attack)
        soup = BeautifulSoup(response.text, 'html.parser')
        # # Use BeautifulSoup to find all <a> tags with the specified format in href
        cve_links = soup.find_all('a',
                                  href=re.compile(r'https://cve.mitre.org/cgi-bin/cvename.cgi\?name=CVE-\d{4}-\d+'))
        if not cve_links:
            sheet.append([attack, 'N/A'])
        else:
            cves = list(set([link.text for link in cve_links]))
            rest_of_row = add_rest_of_row(cves[0])
            sheet.append([attack, '=HYPERLINK("https://www.cvedetails.com/cve/' + cves[0] + '","' + cves[0] + '")'])
            for data in rest_of_row:
                for row in data:
                    if type(row) is list:
                        sheet.append(row)
                    else:
                        sheet.append(data)
            if len(cves) > 1:
                for cve in cves[1:]:
                    # add hyperlinks to the CVEs
                    sheet.append(['', '=HYPERLINK("https://www.cvedetails.com/cve/' + cve + '","' + cve + '")'])
                    rest_of_row = add_rest_of_row(cve)
                    for data in rest_of_row:
                        for row in data:
                            if type(row) is list:
                                sheet.append(row)
                            else:
                                sheet.append(data)
        sheet.append(['', ''])

workbook.save('cves.xlsx')
print("Done!")
print("saved to cves.xlsx :)")



"""
def get_all_related_techniques_by_stix_id(stix_id):
    parents = set(get_all_parents_by_stix_id(stix_id))
    techniques = get_techniques_by_attack_pattern(get_details_of_attack_pattern(stix_id))
    while len(parents) >= 3:
        print("Parents:", parents)
        parent = parents.pop()
        parent_techniques = get_details_of_attack_pattern(parent)
        if parent_techniques:
            techniques += get_techniques_by_attack_pattern(parent_techniques)
        parents.update(get_all_parents_by_stix_id(parent))  # Update with parents of current parent

    return techniques
"""
