## The Hamburglar

<p align="center">
    <img src="https://user-images.githubusercontent.com/7833164/51336290-29a79600-1a52-11e9-96a1-beac9207fdab.gif"></img>
</p>


## Setup

There are 2 versions of hamburglar, full and lite. The main branch is the full version, and hamburglar lite is on a separate branch.

**Hamburglar**

Full fledged scraping tool for artifact retrieval from multiple sources. There are some dependencies, so install them first: 

`pip3 install -r requirements.txt`

**Hamburglar Lite**

Multithreaded and recursive directory scraping script. Stores useful information with the filepath and finding. Hamburglar lite will never require external packages, and will always remain as a single script. Setup is as simple as requesting the file and using it:

`wget https://raw.githubusercontent.com/needmorecowbell/Hamburglar/hamburglar-lite/hamburglar-lite.py`

This is designed to be quickly downloaded and executed on a machine.


## Operation

```
usage: hamburglar.py [-h] [-v] [-w] [-o FILE] [-y YARA] [-g] path

positional arguments:
  path                  path to directory, url, or file, depending on flag
                        used

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         increase output verbosity
  -w, --web             sets Hamburgler to web request mode, enter url as path
  -o FILE, --out FILE   write results to FILE
  -y YARA, --yara YARA  use yara ruleset for checking
  -g, --git             sets hamburglar into git mode

```


**Directory Traversal**

- `python3 hamburglar.py ~/Directory/`
    - This will recursively scan for files in the given directory, then analyzes each file for a variety of findings using regex filters

**Single File Analysis**

- `python3 hamburglar.py ~/Directory/file.txt`
    - This will recursively scan for files in the given directory, then analyzes each file for a variety of findings using regex filters

**YARA Rule Based Analysis**
- `python3 hamburglar.py -y rules/ ~/Directory`
    - This will compile the yara rule files in the rules directory and then check them against every item in Directory.

**Git Scraping Mode**

- `python3 hamburglar.py -g https://www.github.com/needmorecowbell/Hamburglar`
    - Adding `-y <rulepath>` will allow the repo to be scraped using yara rules

**Web Request Mode**

- `python3 hamburglar.py -w https://google.com`
    - Adding a `-w` to hamburgler.py tells the script to handle the path as a url. 
    - Currently this does not spider the page, it just analyzes the requested html content

**Tips**

- Adding `-v` will set the script into verbose mode, and `-h` will show details of available arguments
- Adding `-o FILENAME` will set the results filename, this is especially useful in scripting situations where you might want multiple results tables (ie github repo spidering)

## Settings

- `whitelistOn`: turns on or off whitelist checking
- `maxWorkers`: number of worker threads to run concurrently when reading file stack 
- `whitelist`: list of files or directories to exclusively scan for (if whitelistOn=True)
- `blacklist`: list of files, extensions, or directories to block in scan
- `regexList`: dictionary of regex filters with filter type as the key

## The Hamburglar can find

- ipv4 addresses (public and local)
- emails
- private keys
- urls
- cryptocurrency addresses

## Example output:

```json
{
    "/home/adam/Dev/test/email.txt": {
        "emails": "{'testingtesting@gmail.com'}"
    },
    "/home/adam/Dev/test/email2.txt": {
        "emails": "{'loall@gmail.com'}"
    },
    "/home/adam/Dev/test/ips.txt": {
        "ipv4": "{'10.0.11.2', '192.168.1.1'}"
    },
    "/home/adam/Dev/test/test2/email.txt": {
        "emails": "{'ntested4@gmail.com', 'ntested@gmail.com'}"
    },
    "/home/adam/Dev/test/test2/ips.txt": {
        "ipv4": "{'10.0.11.2', '192.168.1.1'}"
    },
    "/home/adam/Dev/test/test2/links.txt": {
        "site": "{'http://login.web.com'}"
    }
}
```
## Notes

- Inspiration came from needmorecowbell/sniff-paste, I wanted the same regex scraping but for every file in a given directory. 

- Please contribute! If there's an error let me know -- even better if you can fix it :)
	- Regex Contributions would be very helpful, and should be pretty easy to add!
- Please don't use this project maliciously, it is meant to be an analysis tool
