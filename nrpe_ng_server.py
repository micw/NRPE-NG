#!/usr/bin/python

from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from subprocess import Popen, PIPE, STDOUT
import re
import time
import logging
import md5

logging.basicConfig(level=logging.DEBUG)


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
AUTH_USERS={
	'x': 'y'
}

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
					self.sendResponse(STATUS_CRITICAL,"NRPE: Command '"+commandName+
						"' was terminated by signal "+(-retcode)+"\n")
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
		self.sendResponse(STATUS_CRITICAL,"NRPE: Authentication failed (configuration error)\n",401)
		return 0;

	def authDigest(self):
		authHeader=self.headers.getheader('Authorization')
		CURRENT_NONCE = int(round(time.time() * 1000));
		MIN_VALID_NONCE = CURRENT_NONCE-5000 # A nonce is valid for 5 seconds
		if authHeader == None:
			logging.debug("Got request without authentication header.")
		else:
			logging.debug("Got request with authentication header: %s" % authHeader)
			reg=re.compile('(\w+)[:=] ?"?(\w+)"?')
			authHeaderFields=dict(reg.findall(authHeader))
			if authHeaderFields.has_key('nonce') and authHeaderFields.has_key('response') and authHeaderFields.has_key('username'):
				# TODO:
				OTHERS_NONCE=long(authHeaderFields['nonce'])
				OTHERS_RESPONSE=authHeaderFields['response']
				OTHERS_USERNAME=authHeaderFields['username']

				if OTHERS_NONCE>=MIN_VALID_NONCE and OTHERS_NONCE<=CURRENT_NONCE:
					logging.debug("Nonce is valid, checking response")

					if AUTH_USERS.has_key(OTHERS_USERNAME):
						# Digest auth, see https://en.wikipedia.org/wiki/Digest_access_authentication
						logging.debug("Username is known: %s" % OTHERS_USERNAME)
						HA1=md5.new()
						HA1.update(OTHERS_USERNAME)
						HA1.update(":")
						HA1.update(AUTH_REALM)
						HA1.update(":")
						HA1.update(AUTH_USERS[OTHERS_USERNAME])
						HA2=md5.new()
						HA2.update(self.command)
						HA2.update(":")
						HA2.update(self.path)
						HA2=m.hexdigest()
						RES=md5.new()
						RES.update(HA1.hexdigest())
						RES.update(":")
						RES.update(str(OTHERS_NONCE))
						RES.update(":")
						RES.update(HA2.hexdigest())
						EXPECTED_RESPONSE=m.hexdigest()
						if EXPECTED_RESPONSE==OTHERS_RESPONSE:
							logging.debug("Authentication succeeded.")
							return 1
						else:
							logging.info("Authentication failed. Expected response %s but got %s" % (EXPECTED_RESPONSE,OTHERS_RESPONSE))
					else:
						logging.info("Username is unknown: %s" % OTHERS_USERNAME)
				else:
					logging.info("Nonce is invalid.")
			else:
				logging.info("Authentication header is missing nonce, response or username: %s" % authHeader)

		# Not yet authenticated - start digest challenge/response
		CURRENT_NONCE = int(round(time.time() * 1000));
		self.sendResponse(STATUS_CRITICAL,"NRPE: Unauthorized\n",401,'Digest realm="%s" nonce="%s"' % 
			(AUTH_REALM, CURRENT_NONCE))
		return 0;

	def sendResponse(self,nrpeStatusCode,message,httpCode=200,authHeader=""):
		self.send_response(httpCode)
		self.send_header("Content-type", "text/plain")
		self.send_header("X-NRPE-STATUS", nrpeStatusCode)
		if authHeader != "":
			self.send_header("WWW-Authenticate", authHeader)
		self.end_headers()
		self.wfile.write(message)


logging.info("Running server at %s:%s" % (BIND_ADDRESS,PORT))

httpd=HTTPServer((BIND_ADDRESS,PORT),MyHandler)
httpd.serve_forever()
