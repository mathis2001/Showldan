# Showldan
Reconnaissance tool using shodan API to find juicy stuff during bug hunting.

## Prerequisites:

- shodan
- argparse

## Install:
```bash
$ git clone https://github.com/mathis2001/Showldan

$ cd Showldan

$ python3 showldan.py
```
## Usage:

To use this tool, you'll have to get your shodan.io api key at https://account.shodan.io/ and put it in your variable environment under the name "SHODAN".
Then, you can use the tool as follow:

```bash
./showldan.py [-t target domain] [-s] [-p] [-i] [-d]
```


## Options:
```bash
  -h, --help                      show this help message and exit
  
  -t, --target                    Target domain
  
  -s, --exposed-services          Search for exposed services
  
  -p, --default-pass              Search for default credentials
  
  -i, --info-disclosure           Search for information disclosure
  
  -d, --domain-takeover           Search for domain takeover
  
  -l, --limit                     Limit of responses fetched
```
## Screenshots:

![image](https://user-images.githubusercontent.com/40497633/222154297-a5b53836-f134-4cf9-bd54-c633023ec3ea.png)
