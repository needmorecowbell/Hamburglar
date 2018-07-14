import re
import os
import sys
import threading
import json


if(len(sys.argv) != 2):
    print("[-] Argument Error: Use hamburglar.py </path/to/file/or/directory>")
    exit()

#Set True to filter by whitelist
whitelistOn= False

#Max workers for reading and sniffing each file
maxWorkers= 20


# Add to whitelist to ONLY sniff certain files or directories
whitelist= [".txt"]

# Add to blacklist to block files and directories
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

# Regex dictionary, comment out a line to stop checking for entry, and add a line for new filters
regexList= {
    "ipv4":"[0-9]+(?:\.[0-9]+){3}",
    "site":"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+",
    "phones":"\(?[2-9][0-9]{2}\)?[-. ]?[2-9][0-9]{2}[-. ]?[0-9]{4}\b",
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

#Get First Argument (file or directory)
passedPath = sys.argv[1]

#only use unique filepaths(should be unique anyways, just redundant)
filestack= set()

cumulativeFindings= {}



def scan():

    # check for directory
    if(os.path.isfile(passedPath)==False):

        for root, subFolders, files in os.walk(passedPath): #iterate through every file in given directory

            for entry in files: #get all files from root directory
                filepath= os.path.join(root,entry)
                if(whitelistOn): #if whitelisted, check if entry is valid and add to stack
                    if(_iswhitelisted(filepath)):
                        print("[+] whitelist finding: "+str(filepath))
                        filestack.add(filepath)
                    else:#if its not, forget about the file
                        break
                elif(_isfiltered(filepath)):#if whitelist is off, check blacklist
                            print("[-] "+filepath+" blacklisted, not scanning")
                            break
                else:#lastly, if it is not blacklisted, lets add the file to the stack
                    try:
                        print("[+] adding:"+str(filepath)+" ("+str(os.stat(filepath).st_size >> 10)+"kb) to stack")
                        filestack.add(filepath)
                    except Exception as e:
                        print("[-] read error: "+str(e) )

            for folder in subFolders: # check every subFolder recursively
                for entry in files:
                    filepath= os.path.join(root,entry)
                    if(whitelistOn): #if whitelisted, check if entry is valid and add to stack
                        if(_iswhitelisted(filepath)):
                            print("[+] whitelist finding: "+str(filepath))
                            filestack.add(filepath)
                        else:#if its not, forget about the file
                            break
                    elif(_isfiltered(filepath)):#if whitelist is off, check blacklist
                                print("[-] "+filepath+" blacklisted, not scanning")
                                break
                    else:#lastly, if it is not blacklisted, lets add the file to the stack
                        try:
                            print("[+] adding:"+str(filepath)+" ("+str(os.stat(filepath).st_size >> 10)+"kb) to stack")
                            filestack.add(filepath)
                        except Exception as e:
                            print("[-] read error: "+str(e) )

    else: #we just have a single file, so add it to the stack
        print("[+] single file passed")
        filestack.add(passedPath)


def _isfiltered(filepath):
    for filtered in blacklist:
        if (filtered in filepath): return True
    return False

def _iswhitelisted(filepath):
    for filtered in whitelist:
        if (filtered in filepath): return True
    return False

def _file_read():
    while(filestack): #while there are still items on the stack/worker pool...
        filepath= filestack.pop()
        print("[+] left on stack: "+str(len(filestack)))
        try:
            with open(filepath, "rb") as scanfile: #open file on stack that needs sniffed
                print("[+] file: "+filepath)

                filestring = str(scanfile.read()).rstrip('\r\n') # turn file to string and clean it of newlines
                results = _sniff_text(filepath,filestring) #get dictionary of results from regex search

                if (len(results.items())>0): # if we found something in the file, add it to the findings report
                    print("[+] results found")
                    cumulativeFindings.update({filepath:results})

        except Exception as e:
            print("[-] "+filepath+": can't be read: "+str(e))



def _sniff_text(filePath, text):
    results= {}
    for key, value in regexList.items(): # check every regex for findings, and return a dictionary of all findings
        findings= set(re.findall(value, text))
        if(findings):
            results.update({key:findings})
    return results

def displayCumulative(): #Displays finding report
    print(json.dumps(dict(cumulativeFindings), default=lambda x: str(x), sort_keys=True, indent=4))

def _write_to_file(): # Writes report to json file
    with open('hamburglar-results.json', 'w') as file:
        file.write(json.dumps(dict(cumulativeFindings), default=lambda x: str(x), sort_keys=True, indent=4))


if __name__ == "__main__":
    print("[+] scanning...")
    scan()
    print("[+] scan complete")

    workers= [] # workers to handle filestack
    for x in range(maxWorkers):#start up file reading worker threads
        t=threading.Thread(target=_file_read)
        t.start()
        workers.append(t)

    for worker in workers:# join all workers to conclude scan
        worker.join()

    print("[+] writing to hamburglar-results.json...")
    _write_to_file()
    print("[+] The Hamburglar has finished snooping")
