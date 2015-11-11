#!/usr/bin/python

from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from subprocess import Popen, PIPE, STDOUT

VERSION="0.1"
STATUS_OK=0
STATUS_WARNING=1
STATUS_CRITICAL=2
STATUS_UNKNOWN=3

BIND_ADDRESS="127.0.0.1"
PORT=8000
COMMANDS={
	'check_disk': '/usr/lib/nagios/plugins/check_disk -w 80% -c 10% -p /'
}
# none|digest
AUTH_SCHEME="digest"
AUTH_REALM="restricted"

class MyHandler(BaseHTTPRequestHandler):
	def do_GET(self):
		self.do_POST()

	def do_POST(self):
		if not self.auth():
			return;
		commandName=self.path.strip("/")

		if commandName == "":
			self.sendResponse(STATUS_OK,"NRPE-NG: v"+VERSION+"\n")
		elif COMMANDS.has_key(commandName):
			try:
				command=COMMANDS[commandName]
				# TODO: Timeout
				p = Popen(command, shell=True, stdout=PIPE, stderr=STDOUT, close_fds=True)
				(resultMessage, nothingelse) = p.communicate()
				retcode = p.returncode
				if retcode < 0:
					self.sendResponse(STATUS_CRITICAL,"NRPE: Command '"+commandName+"' was terminated by signal "+(-retcode)+"\n")
				else:
					status=retcode
					if (status>3):
						status=STATUS_CRITICAL # use critical for unknown return code
					self.sendResponse(status,resultMessage)
			except OSError as e:
				self.sendResponse(STATUS_CRITICAL,"NRPE: Command '"+commandName+"' execution failed: "+e+"\n")
		else:
			self.sendResponse(STATUS_CRITICAL,"NRPE: Command '"+commandName+"' not defined\n")

	def auth(self):
		if AUTH_SCHEME == "none":
			return 1;
		if AUTH_SCHEME == "digest":
			return self.authDigest();
		self.sendResponse(STATUS_CRITICAL,"NRPE: Authentication failed\n",401)
		return 0;

	def authDigest(self):
		# TODO: inclomplete
		self.sendResponse(STATUS_CRITICAL,"NRPE: Unauthorized\n",401,'Digest realm="%s" nonce="%s"' % 
			(AUTH_REALM, "dcd98b7102dd2f0e8b11d0f600bfb0c093"))
		return 0;

	def sendResponse(self,nrpeStatusCode,message,httpCode=200,authHeader=""):
		self.send_response(httpCode)
		self.send_header("Content-type", "text/plain")
		self.send_header("X-NRPE-STATUS", nrpeStatusCode)
		if authHeader != "":
			self.send_header("WWW-Authenticate", authHeader)
		self.end_headers()
		self.wfile.write(message)


httpd=HTTPServer((BIND_ADDRESS,PORT),MyHandler)
httpd.serve_forever()
