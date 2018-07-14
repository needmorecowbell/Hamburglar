## The Hamburglar

<p align="center">
    <img src="res/hamburglar.jpg" width="250"></img>
</p>

Multithreaded and recursive directory scraping script. Stores useful information with the filepath and finding. All in one file, no external packages required! 

## Operation

`python3 hamburgler.py ~/Directory/Here`

This will recursively scan for files, then analyzes each file for a variety of findings using regex filters

## The Hamburglar can find

- ipv4 addresses (public and local)
- emails
- private keys
- urls
- cryptocurrency addresses


## Notes

- Inspiration came from needmorecowbell/sniff-paste, I wanted the same regex scraping but for every file in a given directory. 

- Please contribute! If there's an error let me know -- even better if you can fix it :)
	- Regex Contributions would be very helpful, and should be pretty easy to add!
- Please don't use this project maliciously, it is meant to be an analysis tool
