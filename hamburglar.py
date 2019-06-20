import re
import os
import sys
import threading
import json
from urllib.request import urlopen
import argparse
import sqlalchemy as db
import configparser
import yara
import iocextract
import os
from newspaper import Article


whitelistOn= False #Set True to filter by whitelist

maxWorkers= 20 #Max workers for reading and sniffing each file

whitelist= [".txt",".html",".md"] # Add to whitelist to ONLY sniff certain files or directories


# Add to blacklist to block files and directories
blacklist = [
    ".git/objects/",
    ".git/index",
    "/node_modules/",
    "vendor/gems/",
    ".iso",
    ".bundle",
    ".png",
    ".jpg",
    ".crt",
    ".exe",
    ".gif",
    ".mp4",
    ".mp3"
]

# Regex dictionary, comment out a line to stop checking for entry, and add a line for new filters
regexList= {
    "AWS API Key": "AKIA[0-9A-Z]{16}",
#    "bitcoin-address" : "[13][a-km-zA-HJ-NP-Z1-9]{25,34}" ,
    "bitcoin-cash-address":"(?:^[13][a-km-zA-HJ-NP-Z1-9]{33})",
    "bitcoin-uri" : "bitcoin:([13][a-km-zA-HJ-NP-Z1-9]{25,34})" ,
    "bitcoin-xpub-key" : "(xpub[a-km-zA-HJ-NP-Z1-9]{100,108})(\\?c=\\d*&h=bip\\d{2,3})?" ,
    "dash-address":"(?:^X[1-9A-HJ-NP-Za-km-z]{33})",
    "dogecoin-address":"(?:^D{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32})",
    "email":"[a-z0-9\.\-+_]+@[a-z0-9\.\-+_]+\.[a-z]+",
    "ethereum-address": "(?:^0x[a-fA-F0-9]{40})",
    "Facebook Oauth": "[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*['|\"][0-9a-f]{32}['|\"]",
    "Generic Secret": "[s|S][e|E][c|C][r|R][e|E][t|T].*['|\"][0-9a-zA-Z]{32,45}['|\"]",
    "GitHub": "[g|G][i|I][t|T][h|H][u|U][b|B].*[['|\"]0-9a-zA-Z]{35,40}['|\"]",
    "Google Oauth": "(\"client_secret\":\"[a-zA-Z0-9-_]{24}\")",
    "Heroku API Key": "[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
    "ipv4":"[0-9]+(?:\.[0-9]+){3}",
    "litecoin-address":"(?:^[LM3][a-km-zA-HJ-NP-Z1-9]{26,33})",
    "monero-address": "(?:^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93})",
    "neo-address":"(?:^A[0-9a-zA-Z]{33})",
    "PGP private key block": "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "phone":"\(?\\b[2-9][0-9]{2}\)?[-. ]?[2-9][0-9]{2}[-. ]?[0-9]{4}\\b",
    "ripple-address":"(?:^r[0-9a-zA-Z]{33})",
    "RSA private key": "-----BEGIN RSA PRIVATE KEY-----",
    "site":"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+",
    "Slack Token": "(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
    "SSH (DSA) private key": "-----BEGIN DSA PRIVATE KEY-----",
    "SSH (EC) private key": "-----BEGIN EC PRIVATE KEY-----",
    "SSH (OPENSSH) private key": "-----BEGIN OPENSSH PRIVATE KEY-----",
    "Twitter Oauth": "[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*['|\"][0-9a-zA-Z]{35,44}['|\"]"
}


parser = argparse.ArgumentParser()
parser.add_argument("-g", "--git", action="store_true",
                    help="sets hamburglar into git mode")
parser.add_argument("-x", "--hexdump", action="store_true",
                     help="give hexdump of file")
parser.add_argument("-v", "--verbose", help="increase output verbosity",
                    action="store_true")

parser.add_argument("-w","--web", help="sets Hamburgler to web request mode, enter url as path",
                    action="store_true")
parser.add_argument("-i","--ioc", help="uses iocextract to parse contents", action="store_true")
parser.add_argument("-o", "--out", dest="output",
                    help="write results to FILE", metavar="FILE")

parser.add_argument("-y", "--yara", dest="yara",
                    help="use yara ruleset for checking")

parser.add_argument("path", help="path to directory, url, or file, depending on flag used")

args= parser.parse_args()

#Get Path Argument (file url or directory)
passedPath = args.path

if args.output is None:
    if args.git:
        outputFilename= args.path[args.path.rfind("/")+1:]+".json"
    else:
        outputFilename= "hamburglar-results.json"
else:
    outputFilename= args.output


#only use unique filepaths(should be unique anyways, just redundant)
filestack= set()
requestStack= set()

cumulativeFindings= {}

def webScan():
    """ Scans the url given in the path, then adds to request stack (eventually this may be a spider)"""
    requestStack.add(passedPath)

def scan():
    """ scans the directory for files and adds them to the filestack """
    # check for directory
    if(os.path.isfile(passedPath)):
        #we just have a single file, so add it to the stack
        print("[+] single file passed")
        filestack.add(passedPath)
        return
    for root, _, files in os.walk(passedPath):     #iterate through every file in given directory
        for entry in files:     #get all files from root directory
            filepath= os.path.join(root,entry)
            if(whitelistOn and _iswhitelisted(filepath)):
                print("[+] whitelist finding: "+str(filepath))
                filestack.add(filepath)
            elif _isfiltered(filepath):
                #if whitelist is off, check blacklist
                if(args.verbose): print("[-] "+filepath+" blacklisted, not scanning")
            else:
                #lastly, if it is not blacklisted, lets add the file to the stack
                try:
                    print("[+] adding:"+str(filepath)+" ("+str(os.stat(filepath).st_size >> 10)+"kb) to stack")
                    filestack.add(filepath)
                except Exception as e:
                    print("[-] read error: "+str(e) )

def _isfiltered(filepath):
    """ checks if the file is blacklisted """
    for filtered in blacklist:
        if (filtered in filepath): return True
    return False

def _iswhitelisted(filepath):
    """ checks if the file given is whitelisted """
    for filtered in whitelist:
        if (filtered in filepath): return True
    return False

def _url_read():
    """ opens the urls in requestStack, makes request, and if something matches the regex, add it to the cumulativeFindings """

    while(requestStack): # while there are still requests to be made
        url=requestStack.pop()
        if(args.verbose):print("[+] left on stack: "+str(len(requestStack)))

        try:
            #with urlopen(url) as response:
            article = Article(url)
            article.download()
            article.parse()
                # html = response.read()
                # data= str(html).rstrip("\r\n")
            results= _sniff_text(article.text)

            if(len(results.items())>0):
                totalResults=sum(map(len, results.values()))
                print("[+] "+url+" -- "+str(totalResults)+" result(s) found.")
                cumulativeFindings.update({url:results})

        except Exception as e:
            print("Url Worker Error: "+str(e))


def _file_read():
    """ opens the files in filestack, reads them , and if something is found in the file that matches the regex, adds them to cumalativeFindings"""
    while(filestack): #while there are still items on the stack/worker pool...
        filepath= filestack.pop()
        if(args.verbose): print("[+] left on stack: "+str(len(filestack)))
        try:
            with open(filepath, "r") as scanfile: #open file on stack that needs sniffed

                filestring = str(scanfile.read()).rstrip('\r\n') # turn file to string and clean it of newlines
                results = _sniff_text(filestring) #get dictionary of results from regex search

                if (len(results.items())>0): # if we found something in the file, add it to the findings report
                    totalResults=len(results.items())
                    print("[+] "+filepath+" -- "+str(totalResults)+" result(s) found.")
                    cumulativeFindings.update({filepath:results})

        except Exception as e:
            print("[-] "+filepath+": can't be read: "+str(e))


def _sniff_text(text ):
    """ checks every regex for findings, and return a dictionary of all findings """
    results= {}
    if(args.ioc):
        print("")
        urls = list(iocextract.extract_urls(text))
        ips = list(iocextract.extract_ips(text))
        if(urls):
            results.update({"urls": urls})
            results.update({"ips": ips})
    else:
        for key, value in regexList.items():
            findings= set(re.findall(value, text))
            if findings:
                results.update({key:findings})
    return results

def displayCumulative():
    """ Displays finding report """
    print(json.dumps(dict(cumulativeFindings), default=lambda x: str(x), sort_keys=True, indent=4))

def _write_to_file(fname):
    """ writes report to json file """
    print("[+] writing to " + outputFilename + "...")
    with open(fname, 'w') as file:
        file.write(json.dumps(dict(cumulativeFindings), default=lambda x: str(x), sort_keys=True, indent=4))

def get_offset(offsets):
    formatted_offset = []
    if offsets is None:
        return formatted_offset

    for offset in offsets.split():
        if re.search('0[xX][0-9a-fA-F]+', offset):
            if len(offset) <= 6:
                formatted_offset.append(int(offset, 16))
            else:
                formatted_offset.append(int(offset[0:6], 16))
                formatted_offset.append(int(offset[6:12], 16))
        else:
            return [0]
    return formatted_offset

def convert_to_regex(hex):
    hex = "".join(hex.split())
    hex = re.sub('\?+', '(.?)', hex)
    hex_list = hex.split('(.?)')
    hex_complete = ""
    for hex_str in hex_list:
        for i in range(0, len(hex_str)):
            i = i * 2
            hex_complete += " " + hex_str[i:i + 2]
        hex_complete += "(.+)"
    hex_complete = " ".join(hex_complete.split())
    return hex_complete[:-4]

def compare_signature():
    config = configparser.ConfigParser()
    config.read('ham.conf')
    sql_user = config['mySql']['user']
    sql_pass = config['mySql']['password']
    conn_String = 'mysql+pymysql://' + sql_user + ':' + sql_pass +'@localhost/fileSign'
    db_engine = db.create_engine(conn_String)
    conn = db_engine.connect()
    signatures = conn.execute("SELECT * FROM signatures").fetchall()

    with open(args.path, "rb") as faile:
        fileHeader = faile.read()
        s1 = " ".join([f"{i:02x}" for i in fileHeader])

        for signs in signatures:
            sig_list = signs[1].split('\n')
            for sigs in sig_list:
                if sigs == "":
                    continue
                sigs_regex = convert_to_regex(sigs).strip()
                offset = get_offset(signs[3])
                for offs in offset:
                    if re.match(sigs_regex, s1[offs:len(sigs) + offs]):
                        print("File format --> ", signs[4])

def hexDump():
    try:
        with open(args.path, "rb") as f:
            n = 0
            b = f.read(16)
            outputFilename = "hexdump.txt"
            print("[+] writing to " + outputFilename + "...")
            with open(outputFilename, 'w') as file:
                while b:
                    s1 = " ".join([f"{i:02x}" for i in b])
                    s1 = s1[0:23] + "  " + s1[23:]
                    s2 = "".join([chr(i) if 32 <= i <= 127 else "." for i in b])

                    file.write(f"{n*16:08x}  {s1:<48}  |{s2}|\n")

                    n += 1
                    b = f.read(16)

    except Exception as e:
        print(__file__, ": ", type(e).__name__, " - ", e, sep="", file=sys.stderr)

def isMatch(rule, target_path):
    #rule = compiled yara rules
    m = rule.match(target_path)
    if m:
        return True
    else:
        return False


def compileRules(rule_path):
    ruleSet=[]
    for root, sub, files in os.walk(rule_path):
        for file in files:
            #print("\t"+os.path.join(root,file))
            rule = yara.compile(os.path.join(root,file))
            ruleSet.append(rule)
    return ruleSet


def scanTargetDirectory(target_path, ruleSet):
    result = []
    for root, sub, files in os.walk(target_path):
        for file in files: #check each file for rules
            #print("\t"+os.path.join(root,file))
            for rule in ruleSet:
                if(isMatch(rule,os.path.join(root,file))):
                    matches = rule.match(os.path.join(root,file))
                    if(matches):
                        for match in matches:
                            print("\t\tYARA MATCH: "+ os.path.join(root,file)+"\t"+match.rule)
                            result.append({ os.path.join(root,file): match.rule })

    return result

def _startWorkers():
    workerType = _url_read if args.web else _file_read #set scantype based of url or directory/file traverseal

    workers = [] # workers to handle filestack
    for x in range(maxWorkers):#start up file reading worker threads
        t=threading.Thread(target=workerType)
        t.start()
        workers.append(t)

    for worker in workers:# join all workers to conclude scan
        worker.join()

def scanGitRepo(target_path, ruleSet=None , yara=False):

    result = []

    #Clone the repo
    print("Cloning Repo Cloned")
    os.system("git clone "+target_path+" tmp")
    os.chdir("tmp")
    os.system("git log -p >> tmp_git_log")
    os.system("mv tmp_git_log ..")
    os.chdir("..")

    #Git Diff results

    if(yara):
        for root, sub, files in os.walk("tmp"):
            for file in files: #check each file for rules
                for rule in ruleSet:

                    if(isMatch(rule,os.path.join(root,file))):
                        matches = rule.match(os.path.join(root,file))
                        if(matches):
                            for match in matches:
                                print("\t\tYARA MATCH: "+ os.path.join(root,file)+"\t"+match.rule)
                                result.append({ os.path.join(root,file): match.rule })

        if(isMatch(rule, "tmp_git_log")):
            matches = rule.match("tmp_git_log")
            if(matches):
                for match in matches:
                    print("\t\tYARA MATCH: Git Log \t"+match.rule)

    else:

        for root, sub, files in os.walk("tmp"):     #iterate through every file in repo
            for entry in files:     #get all files from root directory
                filepath= os.path.join(root,entry)
                if(whitelistOn and _iswhitelisted(filepath)):
                    print("[+] whitelist finding: "+str(filepath))
                    filestack.add(filepath)
                elif _isfiltered(filepath):
                    #if whitelist is off, check blacklist
                    if(args.verbose): print("[-] "+filepath+" blacklisted, not scanning")
                else:
                    #lastly, if it is not blacklisted, lets add the file to the stack
                    try:
                        print("[+] adding:"+str(filepath)+" ("+str(os.stat(filepath).st_size >> 10)+"kb) to stack")
                        filestack.add(filepath)
                    except Exception as e:
                        print("[-] read error: "+str(e) )


        print("[+] adding: tmp_git_log"+" ("+str(os.stat("tmp_git_log").st_size >> 10)+"kb) to stack")
        filestack.add("tmp_git_log")
        _startWorkers()

    #Remove the repository and log
    os.system("rm  tmp -rf && rm tmp_git_log")

    return result



if __name__ == "__main__":

    print("[+] scanning...")
    if(args.hexdump):
        compare_signature()
        hexDump()
        exit()

    if(args.web):
        webScan()
        _startWorkers()
        _write_to_file(outputFilename)
    elif(args.yara is not None):

        rule_path = args.yara
        print("Loading rules")
        rules = compileRules(rule_path)
        print("Scanning Directory ...")

        if(args.git):
            rule_path = args.yara
            print("Loading rules")
            rules = compileRules(rule_path)
            print("Scanning Directory...")
            cumulativeFindings = scanGitRepo(args.path, rules, yara=True)
        else:
            cumulativeFindings= scanTargetDirectory(args.path, rules)

        print("[+] writing to " +outputFilename +"...")
        with open(outputFilename, 'w') as f:
            json.dump({args.path: cumulativeFindings}, f ,sort_keys=True, indent=4)

    elif(args.git):
        print("Scanning Repository")
        scanGitRepo(args.path)
        print("[+] scan complete")
        _write_to_file(outputFilename)

    else:
        scan()
        _startWorkers()
        print("[+] scan complete")
        _write_to_file(outputFilename)

    print("[+] The Hamburglar has finished snooping")
