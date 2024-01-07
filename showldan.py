import shodan
from os import getenv
import argparse

SHODAPI = getenv("SHODAN")

api = shodan.Shodan(SHODAPI)

parser = argparse.ArgumentParser()
parser.add_argument("-t", "--target", help="Target domain", type=str)
parser.add_argument("-O", "--organization", help="Target organization name", action="store_true")
parser.add_argument("-s", "--exposed-services", help="Search for exposed services", action="store_true")
parser.add_argument("-p", "--default-pass", help="Search for default passwords", action="store_true")
parser.add_argument("-i", "--info-disclosure", help="Search for information disclosure", action="store_true")
parser.add_argument("-d", "--domain-takeover", help="Search for domain takeover", action="store_true")
parser.add_argument("-n", "--no-prefixtag", help="Search without tag before target", action="store_true")
parser.add_argument("-H", "--host-discovery", help="Search for hosts", action="store_true")
parser.add_argument("-l", "--limit", help="Limit of results", type=str)
args= parser.parse_args()

class bcolors:
	OK = '\033[92m'
	WARNING = '\033[93m'
	FAIL = '\033[91m'
	RESET = '\033[0m'
	INFO = '\033[94m'

def banner():
	print('''

	⠀⠀⠀⠀⣄⣀⠀⠀⠀⠀⢀⣀⣀⣠⣤⣤⣄⣀⣀⠀⠀⠀⠀⠀⣀⣠⠀⠀⠀________________________________________⠀
	⠀⠀⠀⠀⠉⠙⠻⢶⣶⡟⠛⠋⠉⠉⠉⠉⠉⠉⠙⠛⢷⣦⣶⠟⠋⠉⠀⠀|+		  showldan@dorker	-  x |
	⠀⠀⠀⠀⠀⠀⣴⣿⣿⣿⣷⣄⠀⠀⠀⠀⠀⠀⢀⣴⣿⣿⣿⣧⠀⠀⠀⠀|________________________________________|
	⠀⠀⠀⠀⠀⢰⣿⣿⠋⠁⠈⢻⣧⡀⠀⠀⠀⣴⡿⠉⠀⠙⢿⣿⡇⠀⠀ |showldan@dorker:~$ options              |
	⠀⠀⠀⠀⠀⠸⣿⣿⡀⠀⠀⢠⣿⣷⡄⢀⣾⣿⣇⠀⠀⠀⣸⣿⡇⠀⠀⠀|⠀⠀                                      |
	⠀⠀⠀⠀⠀⣴⢿⣿⣿⣶⣶⣿⣿⡿⣿⣾⠿⣿⣿⣷⣶⣾⣿⡿⣧⠀⠀⠀|⠀⠀-h, --help                            |
	⠀⠀⠀⠀⣼⠏⠘⣿⠉⠛⠛⠋⠉⠀⠸⡏⠀⠈⠙⠛⠛⠉⣿⡇⠘⣧⠀⠀|⠀⠀-t, --target                          |
	⠀⠀⠀⠀⣿⠀⠀⣿⡀⢠⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⡀⠀⣿⠁⠀⣿⠀⠀|⠀⠀-s, --exposed-services                |
	⠀⠀⠀⠀⣿⡀⠀⢹⡇⠸⣶⡤⠀⢠⡀⢀⡀⠀⢤⣴⡇⢰⡿⠀⢀⣿⠀⠀|⠀⠀-p, --default-pass                    |
	⠀⠀⠀⠀⠘⣷⡀⠈⣿⡀⠈⠀⠀⠀⠛⠛⠁⠀⠀⠁⠀⣾⠃⢀⣼⠇⠀⠀|⠀ -i, --info-disclosure		     |
	⠀⠀⠀⠀⠀⠘⢷⣄⠘⣷⡀⢀⡀⠀⡀⠀⠀⠀⡀⠀⣼⠏⣠⡾⠋⠀⠀⠀|⠀⠀-d, --domain-takeover	             |
	⠀⠀⠀⠀⠀⠀⠀⠙⢷⣼⣷⡌⠻⠟⠁⠀⠻⠿⢃⣼⣯⡾⠛⠁⠀⠀⠀⠀|  -l, --limit                           | ⠀⠀
	⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⣿⠿⣶⣄⣀⣀⣠⣴⡟⢿⡍⠀⠀⠀⠀⠀  |  -O, --organization                    |
	⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⠏⢀⣿⠉⢹⡏⠉⢹⡇⠈⢿⡄⠀⠀⠀⠀  |  -n, --no-prefixtag                    |
	⠀⠀⠀⠀⠀⠀⠀⠀⠘⠋⠀⠈⠃⠀⠘⠃⠀⠈⠃⠀⠈⠛⠀⠀⠀⠀⠀ |________________________________________|
		  by S1rN3tZ

	''')


def ShodanSearch(target, search):
    try:
        query = target+'+'+search
        if args.limit:
            results = api.search(query, limit=args.limit)
        else:
            results = api.search(query)

        print(bcolors.INFO+"[*] "+bcolors.RESET+'Results found for',bcolors.INFO+search.strip()+bcolors.RESET+':',bcolors.FAIL+str(results['total'])+bcolors.RESET)
        for result in results['matches']:
                print(bcolors.OK+"[+] "+bcolors.RESET+'IP: {}'.format(result['ip_str']))
                print(bcolors.OK+"[+] "+bcolors.RESET+'Shodan link: ','https://www.shodan.io/host/{}'.format(result['ip_str']))
                print(bcolors.OK+"[+] "+bcolors.RESET+'Host: {}'.format(result['hostnames']))
                print('-----------------------------------------------------------------------')
    except Exception as e:
        print(bcolors.FAIL+"[!] "+bcolors.RESET+'Error: {}'.format(e))

def main():
	if args.target:
		if args.no_prefixtag:
			prefix = []
			target = args.target
			firstcheck = api.search(target)
			results = str(firstcheck['total'])
			if results == '0':
				print(bcolors.FAIL+"[!] "+bcolors.RESET+'No result found for '+target+' without prefix, script canceled.')
				exit(0)
		elif args.organization:
			prefix = ["org:"]
			targetorg = prefix[0]+args.target
			firstcheck = api.search(targetorg)
			results = str(firstcheck['total'])
			if results == '0':
				print(bcolors.FAIL+"[!] "+bcolors.RESET+'No result found for '+targetorg+", script canceled.")
				exit(0)
		else:
			prefix = ['ssl:','hostname:']
			targetBySSL = prefix[0]+args.target
			targetByHost = prefix[1]+args.target
			firstcheck = api.search(targetBySSL)
			secondcheck = api.search(targetByHost)
			resultSSL = str(firstcheck['total'])
			resultHost = str(secondcheck['total'])
			if resultSSL == '0' and resultHost == '0':
				print(bcolors.FAIL+"[!] "+bcolors.RESET+'No result found for both '+targetBySSL+' and '+targetByHost+", script canceled.")
				exit(0)
		if args.exposed_services:
			print(bcolors.INFO+"[*] "+bcolors.RESET+'Searching exposed services for '+bcolors.INFO+args.target+bcolors.RESET)
			with open("exposed_services.txt", "r") as services:
				for search in services:
					if args.no_prefixtag:
						ShodanSearch(target, search)
					elif args.organization:
						print(bcolors.INFO+"[*] "+bcolors.RESET+'Prefix used: '+bcolors.INFO+prefix[0]+bcolors.RESET)
						ShodanSearch(targetorg, search)
					else:
						print(bcolors.INFO+"[*] "+bcolors.RESET+'Prefix used: '+bcolors.INFO+prefix[0]+bcolors.RESET)
						ShodanSearch(targetBySSL, search)
						print(bcolors.INFO+"[*] "+bcolors.RESET+'Prefix used: '+bcolors.INFO+prefix[1]+bcolors.RESET)
						ShodanSearch(targetByHost, search)

		if args.default_pass:
			print(bcolors.INFO+"\n[*] "+bcolors.RESET+'Searching default passwords for '+bcolors.INFO+args.target+bcolors.RESET)
			with open("default_pass.txt", "r") as defpass:
				for search in defpass:
					if args.no_prefixtag:
						ShodanSearch(target, search)
					elif args.organization:
						print(bcolors.INFO+"[*] "+bcolors.RESET+'Prefix used: '+bcolors.INFO+prefix[0]+bcolors.RESET)
						ShodanSearch(targetorg, search)
					else:
						print(bcolors.INFO+"[*] "+bcolors.RESET+'Prefix used: '+bcolors.INFO+prefix[0]+bcolors.RESET)
						ShodanSearch(targetBySSL, search)
						print(bcolors.INFO+"[*] "+bcolors.RESET+'Prefix used: '+bcolors.INFO+prefix[1]+bcolors.RESET)
						ShodanSearch(targetByHost, search)


		if args.info_disclosure:
			print(bcolors.INFO+"\n[*] "+bcolors.RESET+'Searching information disclosure for '+bcolors.INFO+args.target+bcolors.RESET)
			with open("info_disclosure.txt", "r") as disclosure:
				for search in disclosure:
					if args.no_prefixtag:
						ShodanSearch(target, search)
					elif args.organization:
						print(bcolors.INFO+"[*] "+bcolors.RESET+'Prefix used: '+bcolors.INFO+prefix[0]+bcolors.RESET)
						ShodanSearch(targetorg, search)
					else:
						print(bcolors.INFO+"[*] "+bcolors.RESET+'Prefix used: '+bcolors.INFO+prefix[0]+bcolors.RESET)
						ShodanSearch(targetBySSL, search)
						print(bcolors.INFO+"[*] "+bcolors.RESET+'Prefix used: '+bcolors.INFO+prefix[1]+bcolors.RESET)
						ShodanSearch(targetByHost, search)

		if args.domain_takeover:
			print(bcolors.INFO+"\n[*] "+bcolors.RESET+'Searching domain takeover for '+bcolors.INFO+args.target+bcolors.RESET)
			with open("domain_takeover.txt", "r") as takeover:
				for search in takeover:
					if args.no_prefixtag:
						ShodanSearch(target, search)
					elif args.organization:
						print(bcolors.INFO+"[*] "+bcolors.RESET+'Prefix used: '+bcolors.INFO+prefix[0]+bcolors.RESET)
						ShodanSearch(targetorg, search)
					else:
						print(bcolors.INFO+"[*] "+bcolors.RESET+'Prefix used: '+bcolors.INFO+prefix[0]+bcolors.RESET)
						ShodanSearch(targetBySSL, search)
						print(bcolors.INFO+"[*] "+bcolors.RESET+'Prefix used: '+bcolors.INFO+prefix[1]+bcolors.RESET)
						ShodanSearch(targetByHost, search)

		if args.host_discovery:
                        prefix = 'ssl:'
                        target = prefix+args.target
                        search = ''
                        ShodanSearch(target, search)

try:
	banner()
	main()
except KeyboardInterrupt:
        print(bcolors.FAIL+"[!] "+bcolors.RESET+"Script canceled.")
except Exception as e:
	print(bcolors.FAIL+"[!] "+bcolors.RESET+"Error info:")
	print(e)
