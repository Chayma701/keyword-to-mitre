import re

import requests
from bs4 import BeautifulSoup
import openpyxl

# Create a new Excel workbook and select the active sheet
workbook = openpyxl.Workbook()
sheet = workbook.active
sheet.append(['Attack', 'CVE'])

url = 'https://www.fortiguard.com/search?q='

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
            cves = 'N/A'
        else:
            cves = ', '.join(list(set([link.text for link in cve_links])))
        sheet.append([attack, cves])
workbook.save('cves.xlsx')
print("Done!")
print("saved to cves.xlsx :)")

