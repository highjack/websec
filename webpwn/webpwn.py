import pyfiglet
from colorama import init, Fore, Back, Style
import hashlib
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import os.path
import subprocess
import zipfile
import io
from flask import Flask, request                                                      
import threading
import sqlite3

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Web Exploitation Framework
#     coded by highjack

class webpwn:
    proxy_enabled = False
    proxies = {'http': 'http://192.168.1.222:31337','https': 'http://192.168.1.222:31337',}
    debug_enabled = False
    app = Flask(__name__)
    
    @app.route("/get")
    def get_value():
        name = request.args.get('name')
        return "ok"

    @app.route("/set")
    def set_value():
        con = sqlite3.connect('./data/webpwn.db3')
        sql = "INSERT INTO logs (name, value, ref) VALUES (?, ?, ?)"
        ref = request.headers.get("Referer")
        name = request.args.get('name')
        value = request.args.get('value')
        cur = con.cursor()
        cur.execute(sql, (name, value, ref))    
        con.commit()
        return "{}:{} added to database".format(name, value)

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
       
    
    def build_zip(self, zip_dict, output_file_name):
        if zip_dict != None or output_file_name != None:
            f = io.BytesIO(b"")
            z = zipfile.ZipFile(f, 'w', zipfile.ZIP_DEFLATED)
            for key in zip_dict.keys():
                file_name = key
                contents = zip_dict[file_name]
                z.writestr(file_name, contents)

            z.close()
            zip = open(output_file_name,'wb')
            zip.write(f.getvalue())
            zip.close()
        else:
            self.error("Dictionary of zip items or the filename was not provided")


   
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

    def webserver(self, static_folder, port):
        self.status("Starting Flask Server...")
        threading.Thread(target=self.app.run).start()
        

    
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
                    r = session.post(url, data=data, cookies=cookies, headers=headers, proxies=proxies, verify=False, allow_redirects=redirects, files=file_parameter)
                else:
                    self.error("Local file \"{}\" does not exist".format(file_path))
            else:
                self.error("filepath and file_parameter not set")

        response = r.text
        return response, session

