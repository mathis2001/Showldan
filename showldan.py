import shodan
from os import getenv
import argparse

SHODAPI = getenv("SHODAN")

api = shodan.Shodan(SHODAPI)

parser = argparse.ArgumentParser()
parser.add_argument("-t", "--target", help="Target domain", type=str)
parser.add_argument("-s", "--exposed-services", help="Search for exposed services", action="store_true")
parser.add_argument("-p", "--default-pass", help="Search for default passwords", action="store_true")
parser.add_argument("-i", "--info-disclosure", help="Search for information disclosure", action="store_true")
parser.add_argument("-d", "--domain-takeover", help="Search for domain takeover", action="store_true")
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
	⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⣿⠿⣶⣄⣀⣀⣠⣴⡟⢿⡍⠀⠀⠀⠀⠀  |________________________________________|
	⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⠏⢀⣿⠉⢹⡏⠉⢹⡇⠈⢿⡄⠀⠀⠀⠀
	⠀⠀⠀⠀⠀⠀⠀⠀⠘⠋⠀⠈⠃⠀⠘⠃⠀⠈⠃⠀⠈⠛⠀⠀⠀⠀⠀
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
		prefix = ['ssl.cert.subject.CN:.','hostname:*.']
		targetBySSL = prefix[0]+args.target
		targetByHost = prefix[1]+args.target
		if args.exposed_services:
			print(bcolors.INFO+"[*] "+bcolors.RESET+'Searching exposed services for '+bcolors.INFO+args.target+bcolors.RESET)
			with open("exposed_services.txt", "r") as services:
				for search in services:
					print(bcolors.INFO+"[*] "+bcolors.RESET+'Prefix used: '+bcolors.INFO+prefix[0]+bcolors.RESET)
					ShodanSearch(targetBySSL, search)
					print(bcolors.INFO+"[*] "+bcolors.RESET+'Prefix used: '+bcolors.INFO+prefix[1]+bcolors.RESET)
					ShodanSearch(targetByHost, search)

		if args.default_pass:
			print(bcolors.INFO+"\n[*] "+bcolors.RESET+'Searching default passwords for '+bcolors.INFO+args.target+bcolors.RESET)
			with open("default_pass.txt", "r") as defpass:
				for search in defpass:
					print(bcolors.INFO+"[*] "+bcolors.RESET+'Prefix used: '+bcolors.INFO+prefix[0]+bcolors.RESET)
					ShodanSearch(targetBySSL, search)
					print(bcolors.INFO+"[*] "+bcolors.RESET+'Prefix used: '+bcolors.INFO+prefix[1]+bcolors.RESET)
					ShodanSearch(targetByHost, search)


		if args.info_disclosure:
			print(bcolors.INFO+"\n[*] "+bcolors.RESET+'Searching information disclosure for '+bcolors.INFO+args.target+bcolors.RESET)
			with open("info_disclosure.txt", "r") as disclosure:
				for search in disclosure:
					print(bcolors.INFO+"[*] "+bcolors.RESET+'Prefix used: '+bcolors.INFO+prefix[0]+bcolors.RESET)
					ShodanSearch(targetBySSL, search)
					print(bcolors.INFO+"[*] "+bcolors.RESET+'Prefix used: '+bcolors.INFO+prefix[1]+bcolors.RESET)
					ShodanSearch(targetByHost, search)

		if args.domain_takeover:
			print(bcolors.INFO+"\n[*] "+bcolors.RESET+'Searching domain takeover for '+bcolors.INFO+args.target+bcolors.RESET)
			with open("domain_takeover.txt", "r") as takeover:
				for search in takeover:
					print(bcolors.INFO+"[*] "+bcolors.RESET+'Prefix used: '+bcolors.INFO+prefix[0]+bcolors.RESET)
					ShodanSearch(targetBySSL, search)
					print(bcolors.INFO+"[*] "+bcolors.RESET+'Prefix used: '+bcolors.INFO+prefix[1]+bcolors.RESET)
					ShodanSearch(targetByHost, search)


try:
	banner()
	main()
except KeyboardInterrupt:
        print(bcolors.FAIL+"[!] "+bcolors.RESET+"Script canceled.")
except Exception as e:
	print(bcolors.FAIL+"[!] "+bcolors.RESET+"Error info:")
	print(e)
