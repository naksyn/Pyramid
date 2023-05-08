import http.server
import argparse
import sys
import cgi
import base64
import json
from urllib.parse import urlparse, parse_qs
import ssl
import os
import re
import signal
from Helpers import chacha20
from Helpers import xor
from colorama import init, Fore, Back, Style

#### GLOBAL CONFIG PARAMETERS ####

## starting part of the URL that will be treated as base64encoded and encrypted i.e.: /login/cGFyYW1pa29fcHlkc19kZXBlbmRlbmNpZXMuemlw

encode_encrypt_url="/login/"  
iv=b'12345678'

#### DO NOT MODIFY CONFIG BELOW THIS LINE ###

'''
HTTP server implementation that uses SSL certificate and Basic Authentication.
Generate first SSL certificate and key using:
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365
'''



forbidden_chars = ["../", "~", "`", "&", "|", ";", "$", "{", "}", "[", "]", "(", ")", "<", ">", "'", "\"", "\\"]
begin_delim="### AUTO-GENERATED PYRAMID CONFIG ### DELIMITER"
end_delim="### END DELIMITER"

def replace_in_file(pyramid_params,filename, directory):
	with open(os.path.join(directory, filename), 'r+') as file:
		content = file.read()
		replace_text=begin_delim + '\n\n'
		for key in pyramid_params:
			replace_text += key+pyramid_params[key]+'\n'
		replace_text += '\n' + end_delim
		begin_index = content.find(begin_delim)
		end_index = content.find(end_delim)
		if begin_index != -1 and end_index != -1 and begin_index < end_index:
			toberemoved_text = content[begin_index + len(begin_delim):end_index] #debugging
			file.seek(begin_index)
			file.write(replace_text)
			file.write(content[end_index + len(end_delim):])
			print(Fore.YELLOW + "[+] Text between delimiters removed and replaced on file {}".format(filename) + Style.RESET_ALL)
		else:
			print(Fore.YELLOW + "[!] Delimiters not found in the file {} - might be OK if Pyramid config are not needed for it".format(filename) + Style.RESET_ALL)
						

def substitute_parameters(pyramid_params):
	modules_dir = os.getcwd() + '/Modules'
	agent_dir = os.path.dirname(os.getcwd()) + '/Agent'
	for filename in os.listdir(modules_dir):
		updated_content = ''
		if filename.endswith(".py"):
			replace_in_file(pyramid_params, filename, modules_dir)
	for filename in os.listdir(agent_dir):
		updated_content = ''
		if filename.endswith(".py"):
			replace_in_file(pyramid_params, filename, agent_dir)
	

	
				
				
	


class CustomServerHandler(http.server.BaseHTTPRequestHandler):


	### Encryption wrapper ####

	def encrypt_wrapper(self, data):
		if self.parsed_options.enc == 'xor':
			result=xor.xor(data, self.parsed_options.passenc.encode('utf-8'))
			return result
		elif self.parsed_options.enc == 'chacha20':
			result=chacha20.encrypt(data, self.parsed_options.passenc.encode('utf-8'),iv)
			return result
	
	def sanitize_path(self,encoded=True):
	#Sanitize path to prevent directory traversal attacks
		if base64:
			self.path = self.path.split(encode_encrypt_url)[-1]
			print(Fore.YELLOW + f'[+] Decoding and Decrypting URL: {self.path}' + Style.RESET_ALL)
			self.path=(self.encrypt_wrapper(base64.b64decode(self.path)).decode('utf-8'))
			
			print(Fore.YELLOW + f'[+] Decrypted path: {self.path}' + Style.RESET_ALL)
		for forbidden in forbidden_chars:
			if forbidden in self.path:
				print(Fore.RED + f"Forbidden character {forbidden} in {self.path}" + Style.RESET_ALL) 
				return None
		return self.path.split('/')[-1] #returns the file requested

	def do_HEAD(self):
		self.send_response(200)
		self.send_header('Content-type', 'application/json')
		self.end_headers()

	def do_AUTHHEAD(self):
		self.send_response(401)
		self.send_header(
			'WWW-Authenticate', 'Basic realm="Demo Realm"')
		self.send_header('Content-type', 'application/json')
		self.end_headers()

	def do_GET(self):
		self.parsed_options=options
		key = self.server.get_auth_key()

		''' Present frontpage with user authentication. '''
		if self.headers.get('Authorization') == None:
			self.do_AUTHHEAD()

			response = {
				'success': False,
				'error': 'No auth header received'
			}
		
			self.wfile.write(bytes(json.dumps(response), 'utf-8'))

		elif self.headers.get('Authorization') == 'Basic ' + str(key):
			self.send_response(200)
			self.end_headers()

			getvars = self._parse_GET()

			response = {
				'path': self.path,
				'get_vars': str(getvars)
			}
			
			
			if self.path.startswith(encode_encrypt_url):
				# decode and decrypt the URL if it is base64 encoded
				filename = self.sanitize_path()
				if not filename:
					# forbidden character identified - dropping request
					return
			else:
				# no encoding and no encryption in the URL
				filename = sanitize_path(encoded=False)
			
			ext = filename.split('.')[-1]
			
			if '---' in filename:
				subfolder= filename.split('---')[0]
				filename = filename.split('---')[-1]
				if subfolder == 'delivery_files':
					path = 'Delivery_files'
				if ext == 'zip':
					path = 'Dependencies/' + subfolder
			elif ext == 'py':
				path = 'Modules'
			else: 
				path = '.'

			file_path = os.path.join(path, filename)
			
			try:
				with open(file_path, 'rb') as file_get:
					content = file_get.read()
				
				content= self.encrypt_wrapper(content)									
			   
				self.wfile.write(content)
				print(Fore.YELLOW + f'[+] Delivered encrypted file {file_path}' + Style.RESET_ALL)
				
			except Exception as e:
				print(e)
			
		else:
			self.do_AUTHHEAD()

			response = {
				'success': False,
				'error': 'Invalid credentials'
			}

			
	def do_POST(self):
		key = self.server.get_auth_key()

		''' Present frontpage with user authentication. '''
		if self.headers.get('Authorization') == None:
			self.do_AUTHHEAD()

			response = {
				'success': False,
				'error': 'No auth header received'
			}

			self.wfile.write(bytes(json.dumps(response), 'utf-8'))

		elif self.headers.get('Authorization') == 'Basic ' + str(key):
			self.send_response(200)
			self.send_header('Content-type', 'application/json')
			self.end_headers()

			postvars = self._parse_POST()
			getvars = self._parse_GET()

			response = {
				'path': self.path,
				'get_vars': str(getvars),
				'get_vars': str(postvars)
			}


		else:
			self.do_AUTHHEAD()

			response = {
				'success': False,
				'error': 'Invalid credentials'
			}

			self.wfile.write(bytes(json.dumps(response), 'utf-8'))

		response = {
			'path': self.path,
			'get_vars': str(getvars),
			'get_vars': str(postvars)
		}

		self.wfile.write(bytes(json.dumps(response), 'utf-8'))

	def _parse_POST(self):
		ctype, pdict = cgi.parse_header(self.headers.getheader('content-type'))
		if ctype == 'multipart/form-data':
			postvars = cgi.parse_multipart(self.rfile, pdict)
		elif ctype == 'application/x-www-form-urlencoded':
			length = int(self.headers.getheader('content-length'))
			postvars = cgi.parse_qs(
				self.rfile.read(length), keep_blank_values=1)
		else:
			postvars = {}

		return postvars

	def _parse_GET(self):
		getvars = parse_qs(urlparse(self.path).query)

		return getvars


class CustomHTTPServer(http.server.HTTPServer):
	key = ''

	def __init__(self, address, handlerClass=CustomServerHandler):
		super().__init__(address, handlerClass)

	def set_auth(self, username, password):
		self.key = base64.b64encode(
			bytes('%s:%s' % (username, password), 'utf-8')).decode('ascii')

	def get_auth_key(self):
		return self.key
		
		
if __name__ == '__main__':
	
	parser = argparse.ArgumentParser(description='Serve Pyramid files over HTTP/S and provide basic authentication.')

	default_filesfolder = os.getcwd() + "/"
	default_sslkey = os.path.join(default_filesfolder, 'key.pem')
	default_sslcert = os.path.join(default_filesfolder, 'cert.pem')

	parser.add_argument('-server', '--server',  required='-generate' in sys.argv, type=str, help='server that will be set in modules Pyramid config')
	parser.add_argument('-p', '--port', type=int, help='Port on which the server will be listening', default=80)
	parser.add_argument('-u', '--user', help='HTTP Basic Auth username',required=True)
	parser.add_argument('-pass', '--password', help='HTTP Basic Auth password',required=True)
	parser.add_argument('-ssl', action='store_true', help='Enable SSL encryption with default SSL key and certificate')
	parser.add_argument('-sslkey', help=f'SSL key file full path (default: {default_sslkey})', default=default_sslkey)
	parser.add_argument('-sslcert', help=f'SSL certificate file full path (default: {default_sslcert})', default=default_sslcert)
	parser.add_argument('-filesfolder', help=f'Pyramid Server folder (default: {default_filesfolder})', default=default_filesfolder)
	parser.add_argument('-enc', choices=['xor', 'chacha20'], help='Apply encryption to delivered files and decrypt URLs. XOR and modified chacha schemes are available', required=True)
	parser.add_argument('-generate', action='store_true', help='Generate Pyramid Server configs for modules automatically based on command line given')
	group = parser.add_mutually_exclusive_group(required='-enc' in sys.argv)
	group.add_argument('-passenc', help='Encryption password')
	
	example_usage = 'Example: python3 pyramid.py -u testuser -pass testpass -p 443 -ssl -enc chacha20 -passenc superpass -generate -server 192.168.1.1'
	parser.epilog = example_usage

	


	if len(sys.argv)==1:
		parser.print_help()
		sys.exit(1)

	options = parser.parse_args()
	
	pyramid_params = {'pyramid_server=':'\'' + (options.server if options.server else '') + '\'',
					  'pyramid_port=':'\'' + str(options.port) + '\'',
					  'pyramid_user=':'\'' + options.user + '\'',
					  'pyramid_pass=':'\'' + options.password + '\'',
					  'encryption=':'\'' + options.enc + '\'',
					  'encryptionpass=':'\'' + options.passenc + '\'',
					  'chacha20IV=':str(iv),
					  'pyramid_http=':'\'' + ('https' if options.ssl else 'http') + '\'',
					  'encode_encrypt_url=': '\'' + encode_encrypt_url + '\''}
					  
					  
	
	
	
	# Check that sslkey file exists
	if(options.ssl):
		if not os.path.exists(options.sslkey):
			print(Fore.RED + f'[!] Error - SSL key file not found: {options.sslkey}'+ Style.RESET_ALL)
			print(Fore.GREEN + '[!] To generate a self-signed certificate, run: openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365'+ Style.RESET_ALL)
			exit(1)

	# Check that sslcert file exists
		if not os.path.exists(options.sslcert):
			print(Fore.RED + f'[!] Error - SSL certificate file not found: {options.sslcert}'+ Style.RESET_ALL)
			print(Fore.RED + '[!] To generate a self-signed certificate, run: openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365'+ Style.RESET_ALL)
			exit(1)

	# Check that filesfolder exists
	if not os.path.exists(options.filesfolder):
		print(Fore.RED + f'Pyramid Server folder not found: {options.filesfolder}'+ Style.RESET_ALL)
		exit(1)
		
	# Check that Modules folder exists
	if not os.path.exists(os.path.join(options.filesfolder, 'Modules')):
		print(Fore.RED + f'Modules folder not found under Pyramid Server folder: {os.path.join(options.filesfolder, "Modules")}'+ Style.RESET_ALL)
		exit(1)

	# Check that Dependencies folder exists
	if not os.path.exists(os.path.join(options.filesfolder, 'Dependencies')):
		print(Fore.RED + f'Dependencies folder not found under Pyramid Server folder: {os.path.join(options.filesfolder, "Dependencies")}'+ Style.RESET_ALL)
		exit(1)
	
	# Check if SSL is enabled
	if options.ssl:
		# Use default SSL key and cert if not specified
		if not options.sslkey:
			options.sslkey = default_sslkey
		if not options.sslcert:
			options.sslcert = default_sslcert


	
	def signal_handler(signal, frame):
		print(Fore.YELLOW +'\nExiting server...'+ Style.RESET_ALL)
		server.server_close()
		exit(0)



	print(Fore.GREEN + """
__________                              .__    .___
\______   \___.__.____________    _____ |__| __| _/
 |     ___<   |  |\_  __ \__  \  /     \|  |/ __ | 
 |    |    \___  | |  | \// __ \|  Y Y  \  / /_/ | 
 |____|    / ____| |__|  (____  /__|_|  /__\____ | 
           \/                 \/      \/        \/
 HTTP/S server main features:
 - Auto-generation of server config for modules and cradle (use -generate switch)
 - Basic Authentication
 - encryption of delivered files (chacha, xor)
 - URL decoding and decryption
 
 Version: 0.1 
 Author: @naksyn
		   """ + Style.RESET_ALL)
		   
	
	if options.generate:
		print(Fore.YELLOW + "[+] Auto-generating Pyramid config for modules and agents" + Style.RESET_ALL)
		substitute_parameters(pyramid_params)
	
	print(Fore.YELLOW + "[+] Pyramid HTTP Server listening on port "+ Style.RESET_ALL,options.port)
	print(Fore.YELLOW + "[+] MIND YOUR OPSEC! Serving Pyramid files from folder "+ Style.RESET_ALL,options.filesfolder)
	print(Fore.YELLOW + "[+] User allowed to fetch files: "+ Style.RESET_ALL, options.user)

	if options.ssl:
		print(Fore.YELLOW + "[+] HTTPS Server starting "+ Style.RESET_ALL)
		print(Fore.YELLOW + "[+] Using SSL key "+ Style.RESET_ALL, options.sslkey)
		print(Fore.YELLOW + "[+] Using SSL cert" + Style.RESET_ALL, options.sslcert)
		server = CustomHTTPServer(('', int(options.port)))
		server.socket = ssl.wrap_socket(server.socket, keyfile=options.sslkey, certfile=options.sslcert, server_side=True)
	else:
		print(Fore.YELLOW + "[+] HTTP server starting "+ Style.RESET_ALL)
		server = CustomHTTPServer(('', int(options.port)))

	server.set_auth(options.user, options.password)
	signal.signal(signal.SIGINT, signal_handler)
	server.serve_forever()
