# Showldan
Reconnaissance tool using shodan API automating shodan information gathering process to find juicy stuff during bug hunting. 

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
#Search by domain name
python3 showldan.py -t <target domain> [-s] [-p] [-i] [-d]

#Search by organization name
python3 showldan.py -O -t <organization name> [-s] [-p] [-i] [-d]

#Search by domain name or organization name without prefix tag like "hostname:", "ssl:" or "org:"
python3 showldan.py -n -t <target> [-s] [-p] [-i] [-d]
```


## Options:
```bash
  -h, --help                      show this help message and exit
  
  -t, --target                    Target domain/organization 
  
  -O, --organization              Search by organization name
  
  -n, --no-prefixtag              Search without prefix tag before target
  
  -s, --exposed-services          Search for exposed services
  
  -p, --default-pass              Search for default credentials
  
  -i, --info-disclosure           Search for information disclosure
  
  -d, --domain-takeover           Search for domain takeover
  
  -l, --limit                     Limit of responses fetched
```
## Screenshots:

![image](https://user-images.githubusercontent.com/40497633/222399394-0bde1a6b-bba3-4428-a888-c6b6530a9f76.png)
![image](https://user-images.githubusercontent.com/40497633/222180857-9419ca55-7491-4b16-bad5-146301a8f222.png)
![image](https://user-images.githubusercontent.com/40497633/222180918-64c81e76-5b5c-4506-a438-5e3b1408b651.png)
![image](https://user-images.githubusercontent.com/40497633/222398700-ad36b25f-606a-4c14-bfc3-e37bb0583118.png)


