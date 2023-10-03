from mitreattack.stix20 import MitreAttackData
import openpyxl

mitre_ent = MitreAttackData('MITRE/enterprise-attack.json')
mitre_mobile = MitreAttackData('MITRE/mobile-attack.json')
mitre_ics = MitreAttackData('MITRE/ics-attack.json')

workbook = openpyxl.load_workbook('bdd_ml_attaques.xlsx')
input_sheet = workbook['classement']
column = input_sheet['A']

workbook = openpyxl.Workbook()
sheet = workbook.active
sheet.append(['Cle', 'Technique', 'Tactic'])


# the object STIX type (must be ‘attack-pattern’, ‘malware’, ‘tool’, ‘intrusion-set’, ‘campaign’,
# ‘course-of-action’, ‘x-mitre-matrix’, ‘x-mitre-tactic’, ‘x-mitre-data-source’, or ‘x-mitre-data-component’)
def get_objects_by_content(content, stix_type=None):
    return mitre_ent.get_objects_by_content(content, stix_type, remove_revoked_deprecated=True)


def get_objects_by_name(name, stix_type):
    return mitre_ent.get_objects_by_name(name, stix_type)


def get_tactic_info(tactic_name):
    data = get_objects_by_name(tactic_name, 'x-mitre-tactic')
    if len(data) > 0:
        data = data[0]
        return data['external_references'][0]['external_id'] + ': ' + tactic_name
    else:
        return 'N/A'


for key in column:
    if key.value is not None and key.value != "cle":
        teqs = get_objects_by_content(key.value, 'attack-pattern')
        print("key :", key.value)
        for teq in teqs:
            if key.value.lower() in teq['name'].lower():
                teq_id = teq['external_references'][0]['external_id']
                teq_name = teq['name']
                for tactic in teq['kill_chain_phases']:
                    tactic_info = get_tactic_info(tactic['phase_name'].replace('-', ' ').title())
                    sheet.append([key.value, teq_id + ': ' + teq_name, tactic_info])

workbook.save('technique_tactic.xlsx')
