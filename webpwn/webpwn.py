import pyfiglet
from colorama import init, Fore, Back, Style
import hashlib
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import os.path
import subprocess

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Web Exploitation Framework
#     coded by highjack

class webpwn:
    proxy_enabled = False
    proxies = {'http': 'http://192.168.1.222:31337','https': 'http://192.168.1.222:31337',}
    debug_enabled = False

    def __init__(self, exploit_name, author, date, proxy_enabled=False, debug_enabled=False):
        self.exploit_name = exploit_name
        self.author = author
        self.date = date
        self.proxy_enabled = proxy_enabled
        self.debug_enabled = debug_enabled
        self.banner(self.exploit_name, self.author, self.date)
    
    def error(self, message):
        print("[❌] {}".format(message))
        exit()
    def status(self, message):
        print("[❕] {}".format(message))
    def success(self, message):
        print("[✔️} {}".format(message))
    def debug(self, message):
            if self.debug_enabled == True:
                print("[🐞] {}".format(message))

    def banner(self, exploit_name, author, date):
        logo = pyfiglet.figlet_format("webpwn", font = "cosmike" )
        print("{}{}".format(Fore.RED,logo))
        print("{}[- Exploit -]: {}{}".format(Fore.BLUE,Fore.CYAN,exploit_name))
        print("{}[- Date -]: {}{}".format(Fore.BLUE, Fore.CYAN, date))
        print("{}[- Author -]: {}{}{}".format(Fore.BLUE, Fore.CYAN, author, Style.RESET_ALL))
        self.debug("[+] Proxy Enabled: {}".format(str(self.proxy_enabled)))

   
    def hash(self, method, input):
        m = ""
        if method == "sha512":
            m = hashlib.sha512()
        elif method == "sha1":
            m = hashlib.sha1()
        elif method == "md5":
            m = hashlib.md5()
        elif method == "sha256":
            m = hashlib.sha256()
        else:
            return ""
        m.update(input.encode('ascii'))
        return m.hexdigest()

    def run_command(self, command):
        array_command = command.split(" ")
        process = subprocess.Popen(array_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        process.wait()
        stdout = stdout.decode('ascii')
        stderr = stderr.decode('ascii')
        return stdout, stderr

    
    def request(self, method, url, data=None, session=None, cookies=None, headers=None, useragent=None, redirects=True, file_path=None, file_parameter=None):
        method = method.upper()
        if self.proxy_enabled == False:
            proxies = None
        else:
            proxies = self.proxies
        if useragent != None:
            useragent_dict = {"User-Agent":useragent}
            if headers != None:
                headers.update(useragent_dict)
            else:
                headers= useragent_dict

        if session==None:
            session = requests.Session()

        if method == "GET":
            r = session.get(url, cookies=cookies, headers=headers, proxies=proxies, verify=False, allow_redirects=redirects)
        elif method == "POST":
            r = session.post(url, data=data, cookies=cookies, headers=headers, proxies=proxies, verify=False, allow_redirects=redirects)
        elif method == "UPLOAD":
            if file_path != None and file_parameter != None:
                if os.path.isfile(file_path):
                    filehandle = open(file_path, "rb")
                    file_parameter = {file_parameter: filehandle}
                    self.debug(file_parameter)
                    data = { "submit_import" : "Import"}
                    headers = { 'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0'}
                    print(type(file_parameter))
                    r = session.post(url, data=data, cookies=cookies, headers=headers, proxies=proxies, verify=False, allow_redirects=redirects, files=file_parameter)
                else:
                    self.error("Local file \"{}\" does not exist".format(file_path))
            else:
                self.error("filepath and file_parameter not set")

        response = r.text
        return response, session

