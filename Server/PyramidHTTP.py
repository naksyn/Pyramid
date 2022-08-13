import http.server
import argparse
import sys
import cgi
import base64
import json
from urllib.parse import urlparse, parse_qs
import ssl

'''
Simple HTTP server implementation that uses SSL certificate and Basic Authentication.
Generate first SSL certificate and key using:
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365

Based from https://gist.github.com/kaito834/36e693a3a54057666d28
'''


class CustomServerHandler(http.server.BaseHTTPRequestHandler):

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

            try:
                with open(options.filesfolder+self.path.split('/')[1],'rb') as file_get:
                    content=file_get.read()
                self.wfile.write(content)
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
    
    parser = argparse.ArgumentParser(add_help = True, description = 'Serves Pyramid files over HTTP/S and provide also basic authentication.'
    ' command example: PyramidHTTP.py 443 testuser Sup3rP4ss! /home/user/Pyramid/Server/ /home/user/SSL/')
    parser.add_argument('port', action='store', help='Port on which the server will be listening')
    parser.add_argument('user', action='store', help='HTTP Basic Auth username')
    parser.add_argument('password', action='store', help='HTTP Basic Auth password')
    parser.add_argument('sslkey', action='store', help='SSL key file full path. e.g. /home/user/ssl/key.pem')
    parser.add_argument('sslcert', action='store', help='SSL key file full path. e.g. /home/user/ssl/cert.pem')
    parser.add_argument('filesfolder', action='store', help='Pyramid Server folder')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    
    
    print("""
__________                              .__    .___
\______   \___.__.____________    _____ |__| __| _/
 |     ___<   |  |\_  __ \__  \  /     \|  |/ __ | 
 |    |    \___  | |  | \// __ \|  Y Y  \  / /_/ | 
 |____|    / ____| |__|  (____  /__|_|  /__\____ | 
           \/                 \/      \/        \/
 
 HTTP/S server with Basic Auth                    
           """)
    print("[+] Pyramid HTTP Server listening on port ",options.port)
    print("[+] Serving Pyramid files from folder ",options.filesfolder)
    print("[+] Using SSL key ", options.sslkey)
    print("[+] Using SSL cert ", options.sslcert)
    print("[+] User allowed to fetch files: ", options.user)
    print("[!] ENTER PEM PASSPHRASE BELOW AND PRESS ENTER")
    server = CustomHTTPServer(('', int(options.port)))
    server.socket = ssl.wrap_socket (server.socket, options.sslkey, options.sslcert, server_side=True)
    server.set_auth(options.user, options.password)
    
    
    server.serve_forever()
