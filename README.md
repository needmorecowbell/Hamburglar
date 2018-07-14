## The Hamburglar

<p align="center">
    <img src="res/hamburglar.gif"></img>
</p>

Multithreaded and recursive directory scraping script. Stores useful information with the filepath and finding. All in one file, no external packages required! 

## Operation

`python3 hamburglar.py /path/directory/` or `python3 hamburglar.py /path/file.txt`

This will recursively scan for files, then analyzes each file for a variety of findings using regex filters

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
- Now with single file parameter support!

##Example output:

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
