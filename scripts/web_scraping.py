# Script to web scrape vulnerability information into mongodb

from bs4 import BeautifulSoup
from pymongo import MongoClient
from urllib.request import Request, urlopen
import csv

client = MongoClient('localhost', 27017)
db = client.project
vulns = db.vulnerabilities
vulns.drop()
vulns = db.vulnerabilities

mapping1 = { 'High': 2, 'Low': 1, 'None': 0 }
mapping2 = { 'Admin': 2, 'User': 1, 'None': 0 }

filename = input("Enter CSV file (including extension) to read CVEs from: ")

try:
    with open(filename) as csv_file:
        csv_reader = csv.reader(csv_file)
        for row in csv_reader:
            CVE = row[0]

            url = "https://www.cvedetails.com/cve/" + CVE
            req = Request(url, headers={ 'User-Agent': 'Mozilla/5.0' })
            html_doc = urlopen(req).read()
            soup = BeautifulSoup(html_doc, 'lxml')
            table = soup.find("table", { 'id': 'cvssscorestable', 'class': 'details' })
            field_row = table.findAll("tr")[6]
            field_value = field_row.find("span").string
            gained_access = mapping2[field_value]

            url = "https://nvd.nist.gov/vuln/detail/" + CVE
            html_doc = urlopen(url)
            soup = BeautifulSoup(html_doc, 'lxml')
            tag = soup.find('span', { 'data-testid': 'vuln-cvssv3-pr' })
            if tag:
                field_value = tag.string.strip()
            else:
                field_value = "None" # By default, "None" privileges are required
            required_priv = mapping1[field_value]

            tag = soup.find('span', { 'data-testid': 'vuln-cvssv2-av' })
            attack_vector = tag.string.strip()
            
            # Add entry
            document = {}
            document['cveName'] = CVE
            document['gained_access'] = gained_access
            document['required_priv'] = required_priv
            document['access_vector'] = attack_vector
            vulns.insert_one(document)

    print("Successfully imported CVE details")

except IOError:
    print("File {} does not exist".format(filename))
    exit() 
