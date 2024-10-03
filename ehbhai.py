#!/usr/bin/python3
import re
import pathlib
import docx2txt

def main():
    logo()
    path = input(bcolors.YELLOW +"Enter path to your text/docx file: ")
    match = pathlib.Path("{}".format(path)).suffix
    #print(match)
    if match == '.txt':
        DLine()
        CapitalWordFromTxt(path)
    else:
        DLine()
        CapitalWordFromDocx(path)

def FullForm():
    FullWordList = {"ACL": "Access Control List", "AD": "Active Directory", "AES": "Advanced Encryption Standard", "API": "Application Program Interface", "AUP": "Acceptable Usage Policy", "BIA": "Business Impact Analysis", "CBC": "Cipher Block Chaining", "CBS": "Core Business Solution", "CCTV": "Closed Circuit Television", "CSRF": "Cross-Site Request Forgery", "CSS": "Cascading Style Sheets", "CVSS": "Common Vulnerability Scoring System", "CDP": "Cisco Discovery Protocol", "CIA": "Confidentiality Integrity Accountability", "CSP": "Customer Security Policy", "DB": "Database", "DBMS": "Database Management System", "DC": "Domain Controller", "DR": "Disaster Recovery", "DCE": "Distributed Computing Environment", "DDoS": "Distributed Denial of Service", "DES": "Data Encryption Standard", "DHCP": "Dynamic Host Configuration Protocol", "DLL": "Dynamic Link Loader", "DMZ": "Demilitarized Zone", "DNS": "Domain Name System", "DLP": "Data Leak Prevention", "DoS": "Denial of Service", "DTLS": "Datagram Transport Layer Security", "EOL": "End-of-Life", "EPMAP": "Endpoint Mapper", "FTP": "File Transport Protocol", "GUI": "Graphical User Interface", "HO": "Head Office", "HSTS": "HTTP Strict Transport Security", "HTML": "Hyper Text Markup Language", "HTTP": "Hyper Text Transfer Protocol", "HTTPs": "HTTP Secure", "HIRS": "Human Resource Management System", "GSD": "General Service Department", "IIS": "Internet Information Services", "IP": "Internet Protocol", "IPS": "Intrusion Prevention Systems", "IDS": "Intrusion Detection Systems", "IPLC": "International Private Leased Circuit", "IDOR": "Insecure Direct Object Reference", "IPSec": "Internet Protocol Security", "IRMD": "Integrated Risk Management Department", "ISACA": "Information Systems Audit and Control Association", "ISO": "Information Security Officer", "ISP": "Internet Service Provider", "IT": "Information Technology", "ITIL": "Information Technology Infrastructure Library", "JSP": "Java Server Pages", "JWT": "JSON Web Token", "JSON": "JavaScript Object Notation", "KRA": "Key Responsibility Area", "KRI": "Key Risk Indicator", "LAN": "Local Area Network", "LDAP": "Lightweight Directory Access Protocol", "LDAPs": "LDAP over SSL", "LLDP": "The Link Layer Discovery Protocol", "MAC": "Media Access Control", "MBSS": "Minimum Baseline Security Standard", "MIME": "Multipurpose Internet Mail Extensions", "MIS": "Management Information System", "NETBIOS": "Network Basic Input/ Output System", "NGXT": "Next Generation Threat Prevention", "NMS": "Network Monitoring System", "NOC": "Network Operating Center", "NLA": "Network Level Authentication", "NRB": "Nepal Rastra Bank", "NTP": "Network Time Protocol", "OS": "Operating System", "OEM": "Original Equipment Manufacturer", "OOP": "Object Oriented Programming", "PII": "Personal Identifiable Information", "PC": "Personal Computer", "POC": "Proof Of Concept", "PoC": "Proof of Concept", "PRTG": "Paessler Router Traffic Grapher", "RACI": "Responsible, Accountable, Consulted, and Informed", "RDP": "Remote Desktop Protocol", "RCE": "Remote Code Execution", "RMCB": "Risk Management Committee of Board", "RPC": "Remote Procedure Call", "RPO": "Recovery Point Objective", "RTO": "Recovery Time Objective", "SCP": "Secure Copy Protocol", "SIEM": "Security Information and Event Management", "SL": "Silver Lining Private Limited", "SMB": "Server Message Block", "SMTP": "Simple Mail Transport Protocol", "SNMP": "Simple Network Management Protocol", "SOC": "Security Operations Center", "SQL": "Structured Query Language", "SPOF": "Single Point of Failure", "SSH": "Secured Shell", "TCP": "Transmission Control Protocol", "TCP/IP": "Transport Control Protocol/ Internet Protocol", "TFTP": "Trivial File Transport Protocol", "TOR": "Terms of Reference", "TSA": "Technical Service Agreement", "TOFU": "Trust on First Use", "UDP": "User Datagram Protocol", "URL": "Uniform Resource Locator", "VAPT": "Vulnerability Assessment and Penetration Testing", "VNC": "Virtual Network Computing", "VPN": "Virtual Private Network", "VSAT": "Very Small Aperture Terminal", "WAF": "Web Application Firewall", "WIFI": "Wireless Fidelity", "XHR": "XMLHttp Request", "XML": "Extensible Markup Language", "XSS": "Cross-Site Scripting", "CORS": "Cross-Origin Resource Sharing", "OWASP": "Open Web Application Security Project", "UI": "User Interface", "PT": "Penetration Testing", "VA": "Vulnerability Assessment", "XXE": "XML External Entity", "CEO": "Chief Executive Officer", "CTO": "Cheif Technology Officer", "CEH": "Certified Ethical Hacker", "CISSP": "Certified Information Systems Security Professional", "OSCP": "Offensive Security Certified Professional", "CMS": "Content Management System"}
    return FullWordList

def WordInUpperCase():
    WordList = ['ABBREVIATIONS', 'ACRONYMS', 'AND', 'APPROACH', 'AUDIENCE', 'COMMON', 'CONTENT', 'CONTENTS', 'CONTROLS', ' CRITERIA', 'DELETE', 'DETAILED', 'DISCLAIMER', 'ENGAGEMENT', 'EVALUATION', 'FINDINGS', 'FOR', 'GRADING', 'II', 'III', 'IV', 'VI', 'VII', 'VIII', 'IX', 'XI', 'XII', 'XIII', 'XIV', 'XV', 'XVI', 'XVII', 'XVIII', 'XIX', 'XX','INTRODUCTION', 'LEVEL', 'METHODOLOGY', 'OBJECTIVE', 'OBJECTIVES', 'OF', 'PAGE', 'SECTION', 'PPROACH', 'POST', 'GET', 'CRITERIA', 'OpenVas', 'JavaScript', 'RECOMMENDATIONS', 'RESTRICTIONS', 'RISK', 'SCOPE', 'SECTION', 'SEVERITY', 'TABLE', 'TECHNOLOGIES', 'TEST', 'THE', 'TOOLS', 'USED', 'VULNERABILITIES', 'ACCOUNTS', 'ADDRESS', 'ANNEXURE', 'CONTROLLERS', 'DEPARTMENT', 'DOMAIN', 'ENTERPRISE', 'IPADDRESS', 'LOCAL', 'VALUE', 'SERVER', 'SYSTEM', 'SERVICE']
    return WordList

class bcolors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    WHITE = '\033[97m'

def logo():
    print(bcolors.RED + '''
________________________________________________________________________________________

░█████╗░██████╗░██████╗░██████╗░███████╗██╗░░░██╗░█████╗░████████╗██╗░█████╗░███╗░░██╗ 
██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔════╝██║░░░██║██╔══██╗╚══██╔══╝██║██╔══██╗████╗░██║ 
███████║██████╦╝██████╦╝██████╔╝█████╗░░╚██╗░██╔╝███████║░░░██║░░░██║██║░░██║██╔██╗██║ 
██╔══██║██╔══██╗██╔══██╗██╔══██╗██╔══╝░░░╚████╔╝░██╔══██║░░░██║░░░██║██║░░██║██║╚████║ 
██║░░██║██████╦╝██████╦╝██║░░██║███████╗░░╚██╔╝░░██║░░██║░░░██║░░░██║╚█████╔╝██║░╚███║ 
╚═╝░░╚═╝╚═════╝░╚═════╝░╚═╝░░╚═╝╚══════╝░░░╚═╝░░░╚═╝░░╚═╝░░░╚═╝░░░╚═╝░╚════╝░╚═╝░░╚══╝        
				                                                                       
								 By: Dipak Thapa Magar                                 
								 #theycallmenoob07                               
                                                                                       
[*] Only support: .txt and .docx file format                                           
________________________________________________________________________________________
                                                                                        ''')
    
def DLine():
    print(bcolors.WHITE + "\n🇳🇵️🇳🇵️🇳🇵️🇳🇵️🇳🇵️🇳🇵️🇳🇵️🇳🇵️🇳🇵️🇳🇵️🇳🇵️🇳🇵️🇳🇵️🇳🇵️🇳🇵️🇳🇵️🇳🇵️🇳🇵️🇳🇵️🇳🇵️🇳🇵️🇳🇵️🇳🇵️🇳🇵️🇳🇵️🇳🇵️🇳🇵️🇳🇵️🇳🇵️🇳🇵️🇳🇵️🇳🇵️🇳🇵️🇳🇵️🇳🇵️🇳🇵️🇳🇵️🇳🇵️🇳🇵️🇳🇵️🇳🇵️🇳🇵️🇳🇵️🇳🇵️🇳🇵️🇳🇵️🇳🇵️🇳🇵️🇳🇵️🇳🇵️🇳🇵️🇳🇵️\n")
    
    
def PrintResult(finaluniquecollection):
    dictword = FullForm()
    for i in finaluniquecollection:
        if i in dictword:
            print(bcolors.GREEN + '''{}: {}'''.format(i, dictword[i]))
        else:
            print(bcolors.YELLOW + '''{}:'''.format(i))

def CapitalWordFromTxt(x):
    try:
        files = open("{}".format(x))
        allcollection = []
        for line in files:
            match = re.findall(r'\b(?:[A-Z][a-z]*){2,}', line)
            if match:
                allcollection.extend(match)
        uniquecollection = [*set(allcollection)]
        uniquecollection.sort()
        finaluniquecollection = [i for i in uniquecollection if i not in WordInUpperCase()]
        #print(finaluniquecollection)
        print(bcolors.GREEN + '''Possible abbrevations extracted from your file {} are: '''.format(x)) 
        DLine()
        PrintResult(finaluniquecollection)
        DLine()
        
    except FileNotFoundError as e:
        print(bcolors.RED + "No such file: {}".format(x))
        DLine()

def CapitalWordFromDocx(x):
    try:
        doc = docx2txt.process("{}".format(x))
        allcollection = []
        match = re.findall(r'\b(?:[A-Z][a-z]*){2,}', doc)
        if match:
            allcollection.extend(match)
        uniquecollection = [*set(allcollection)]
        uniquecollection.sort()
        finaluniquecollection = [i for i in uniquecollection if i not in WordInUpperCase()]
        print(bcolors.GREEN + '''Possible abbrevations extracted from your file {} are: '''.format(x))
        DLine()
        PrintResult(finaluniquecollection)
        DLine()
    except FileNotFoundError as e:
        print(bcolors.RED + "No such file: {}".format(x))
        DLine()

if __name__ == "__main__":
    main()

