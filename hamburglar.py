import re
import os
import sys
import threading
import json


if(len(sys.argv) != 2):
    print("[-] Argument Error: Use hamburglar.py ~/dir/path")
    exit()

rootdir = sys.argv[1]
fileStack= set()
cumulativeFindings= {}

regexList= {
    "ipv4":"[0-9]+(?:\.[0-9]+){3}",
    "site":"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+",
    "phones":"\(?\b[2-9][0-9]{2}\)?[-. ]?[2-9][0-9]{2}[-. ]?[0-9]{4}\b",
    "emails":"[a-z0-9\.\-+_]+@[a-z0-9\.\-+_]+\.[a-z]+",
    "Slack Token": "(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
    "RSA private key": "-----BEGIN RSA PRIVATE KEY-----",
    "SSH (OPENSSH) private key": "-----BEGIN OPENSSH PRIVATE KEY-----",
    "SSH (DSA) private key": "-----BEGIN DSA PRIVATE KEY-----",
    "SSH (EC) private key": "-----BEGIN EC PRIVATE KEY-----",
    "PGP private key block": "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "Facebook Oauth": "[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*['|\"][0-9a-f]{32}['|\"]",
    "Twitter Oauth": "[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*['|\"][0-9a-zA-Z]{35,44}['|\"]",
    "GitHub": "[g|G][i|I][t|T][h|H][u|U][b|B].*[['|\"]0-9a-zA-Z]{35,40}['|\"]",
    "Google Oauth": "(\"client_secret\":\"[a-zA-Z0-9-_]{24}\")",
    "AWS API Key": "AKIA[0-9A-Z]{16}",
    "Heroku API Key": "[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
    "Generic Secret": "[s|S][e|E][c|C][r|R][e|E][t|T].*['|\"][0-9a-zA-Z]{32,45}['|\"]",
    "bitcoin-address" : "[13][a-km-zA-HJ-NP-Z1-9]{25,34}" ,
    "bitcoin-uri" : "bitcoin:([13][a-km-zA-HJ-NP-Z1-9]{25,34})" ,
    "bitcoin-xpub-key" : "(xpub[a-km-zA-HJ-NP-Z1-9]{100,108})(\\?c=\\d*&h=bip\\d{2,3})?" ,
    "monero-address": "(?:^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$)",
    "ethereum-address": "(?:^0x[a-fA-F0-9]{40}$)",
    "litecoin-address":"(?:^[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}$)",
    "bitcoin-cash-address":"(?:^[13][a-km-zA-HJ-NP-Z1-9]{33}$)",
    "dash-address":"(?:^X[1-9A-HJ-NP-Za-km-z]{33}$)",
    "ripple-address":"(?:^r[0-9a-zA-Z]{33}$)",
    "neo-address":"(?:^A[0-9a-zA-Z]{33}$)",
    "dogecoin-address":"(?:^D{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}$)"
}


#iterate through every file in given directory
def scan():
    for root, subFolders, files in os.walk(rootdir):

        for entry in files:
            filePath= os.path.join(root,entry)
            fileStack.add(filePath)

        for folder in subFolders:
            for entry in files:
                filePath = os.path.join(root,entry)
                fileStack.add(filePath)


def _file_read():
    while(fileStack):
        filePath= fileStack.pop()
        try:
            with open(filePath, "r") as scanFile:
                #print("WORKER CALLED: "+filePath+"\n")
                results = _sniff_text(filePath,scanFile.read().replace('\n', ''))
                if (len(results.items())>1):
                    print("[+] Results found\n")
                    cumulativeFindings.update({filePath:results})
                #for line in scanFile:
                    #filePath=filePath
                    #print(line)
        except Exception as e:
            print("[-] "+filePath+": can't be read: ")



def _sniff_text(filepath, text):
    results= {} 
    for key, value in regexList.items():
        findings= set(re.findall(value, text))
        if(len(findings)>0):
            results.update({key:findings})
    return results
   

if __name__ == "__main__": 
    print("[+] Scanning...")
    scan()
    print("[+] Scan Complete")

    # workers to handle fileStack
    workers= []
    for x in range(5):
        t=threading.Thread(target=_file_read)
        t.start()
        workers.append(t)

    for worker in workers:
        worker.join()

    print("[+] The Hamburglar has finished snooping")
    for key, value in cumulativeFindings.items():
        print("File: "+key)
        print("Value:\n"+str(value)+"\n")

    with open('hamburglar-results.json', 'w') as file:
        file.write(json.dumps(dict(cumulativeFindings), default=lambda x: str(x), sort_keys=True, indent=4))
        #    print("\t"+findingType+": "+findingValue)
        #print("\n")
