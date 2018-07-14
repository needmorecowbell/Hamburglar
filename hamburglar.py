import re
import os
import sys
import threading
import json


if(len(sys.argv) != 2):
    print("[-] Argument Error: Use hamburglar.py ~/dir/path")
    exit()


maxWorkers= 12
passedPath = sys.argv[1]
fileStack= set()
cumulativeFindings= {}

blacklist = [
    ".git/objects/",
    ".git/index",
    "vendor/gems/",
    ".iso",
    ".bundle",
    ".png",
    ".jpg",
    ".crt",
    ".exe"

]
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
#FIND BETTER REGEX    "bitcoin-address" : "[13][a-km-zA-HJ-NP-Z1-9]{25,34}" ,
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
    if(os.path.isfile(passedPath)==False):
        for root, subFolders, files in os.walk(rootdir):
            for entry in files:
                filePath= os.path.join(root,entry)
                if(_isFiltered(filePath)):
                    print("[-] "+filePath+" blacklisted, not scanning")
                    break
                else:
                    try:
                        print("[+] Adding:"+str(filePath)+" ("+str(os.stat(filePath).st_size >> 10)+"kb) to stack")
                        fileStack.add(filePath)
                    except Exception as e:
                        print("[-] Read Error: "+str(e) )

            for folder in subFolders:
                for entry in files:
                    filePath = os.path.join(root,entry)
                    if(_isFiltered(filePath)):
                        print("[-] "+filePath+" blacklisted, not scanning")
                        break
                    else:
                        try:
                            print("[+] Adding:"+str(filePath)+" ("+str(os.stat(filePath).st_size >> 10)+"kb) to stack")
                            fileStack.add(filePath)
                        except Exception as e:
                            print("[-] Read Error: "+str(e) )
    else:
        print("[+] Single file passed")
        fileStack.add(passedPath)


def _isFiltered(filepath):
    for filtered in blacklist:
        if (filtered in filepath): return True
    return False

def _file_read():
    while(fileStack):
        filePath= fileStack.pop()
        print("[+] Left on Stack: "+str(len(fileStack)))
        try:
            with open(filePath, "rb") as scanFile:
                print("[+] File: "+filePath+"\n")
                fileString = str(scanFile.read()).replace('\n', '')
                results = _sniff_text(filePath,fileString)
                if (len(results.items())>0):
                    print("[+] Results found\n")
                    cumulativeFindings.update({filePath:results})
                #else:
                #    print("[-] No Results Found\n")
                #for line in scanFile:
                    #filePath=filePath
                    #print(line)
        except Exception as e:
            print("[-] "+filePath+": can't be read: "+str(e))



def _sniff_text(filepath, text):
    results= {}
    for key, value in regexList.items():
        findings= set(re.findall(value, text))
        if(findings):
            #print(str({key:findings}))
            results.update({key:findings})
    return results

def displayCumulative():
    for key, value in cumulativeFindings.items():
        print("File: "+key)
        print("Value:\n"+str(value)+"\n")

def _write_to_file():
    with open('hamburglar-results.json', 'w') as file:
        file.write(json.dumps(dict(cumulativeFindings), default=lambda x: str(x), sort_keys=True, indent=4))


if __name__ == "__main__":
    print("[+] Scanning...")
    scan()
    print("[+] Scan Complete")

    # workers to handle fileStack
    workers= []
    for x in range(maxWorkers):
        t=threading.Thread(target=_file_read)
        t.start()
        workers.append(t)

    for worker in workers:
        worker.join()

    print("[+] Writing to hamburglar-results.json...")
    _write_to_file()

    print("[+] The Hamburglar has finished snooping")
