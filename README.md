# NRPE-NG - a modern alternative to nagios nrpe protocol

## Intention

Nrpe is commonly used for nagios remote checks. An nrpe server is easy to set up and simple to use. Unfortunately the protocol has some serious drawbacks that makes it hard to use nrpe in a secure environment:

* No authentication of client or server
* No authorisation (who can access which checks)
* No secure encryption (nrpe uses anonymous tls which is open to man-in-the-middle attacks)
* Proprietary protocol that makes it hard to setup a gateway to monitor hosts behind a firewall

For the latter the official solution is NSCA which brings extra complexity and forces the use of passive checks which have limited features.

The goal of this project is to pecify (and implement) a modern alternative protocol that solves the problems above

## Protocol design

NRPE-NG is a http based protocol. Using http has a lot of benefits:

* Several authentication methods (Basic/Digest authentication, SSL based client authentication)
* Optional SSL encryption
* Optional URI-based authorisation
* Easy to implement gateway using http reverse proxy, uri mapping or virtual hosts
* Friendly to application firewalls

### URL-scheme

Each check is assigned to a uniqe URL that consists of a base URL and the check command name.

Example 1:

    https://monitored-host.com/nrpe-ng/check_disks

The base URL is "https://monitored-host.com/nrpe-ng/", the check command name is "check_disks". A check command name must only contain the characters "a-z A-Z 0-9 . _ -". Arguments are passed as URL-parameters arg1...argN and must be URI-encoded with UTF-8 character set. Allowed HTTP-Methods are POST and GET.

Example 2:

    https://monitored-host.com/nrpe-ng/check_with_args?arg1=TestArt&arg2=Arg%20with%20whitespaces

### Check response

The http response must be of content type text/plain with charset utf-8. The http status code for successfully executed checks (independent of check result) should be 200.

The response body contains the whole STDOUT output of the check. There is no size limit but clients may close the connection if the response exceeds a certain size.

The check result (0=OK, 1=Warning, 2=Critical, 3=Unknown) is sent via http header "X-NRPE-STATUS". The absence of this header must be interpreted as Critical.

## Security considerations

When not using SSL for transport encryption, http digest authentication should be used. The algorithm should be SHA-1 or better, recommended is SHA-512 (see https://www.iana.org/assignments/http-dig-alg/http-dig-alg.xhtml for a list of algoritms). MD5 should not be used. The nonce should only be valid for one check to prevent replay attacks.

If possible SSL should be used together with basic or digest authentication.

If a server implementation accepts arguments, all passed arguments should be checked (e.g. restricted to a whitelist of certain characters, maximum lenght or against regular expressions).

## Example implementation

### Server: nrpe_ng_server.py

Features:
* Execute pre defined check commands without arguments
* Implement digest authentication







