# OpenVPN image servlet

This service runs a small Express app to allow for creating, retrieving and deleting of client certificates for the OpenVPN Server via an API.

## Required ENV vars

* PORT - port on which the express server runs.
* CA_PASSPHRASE - passphrase for the CA, set up during image deployment.
* KEY_PASSPHRASE - passphrase for the private key, sed for certificate signing.
* USER_TOKENS - available user names in plain text, comma-separated.

## API

Each call marked with **authorized** requires a `token` parameter in its query. This parameter must match MD5 hash of one of registered user tokens.

### GET /

Heartbeat.

### POST /cert?name=CLIENT_NAME&ip=STATIC_VPN_IP&token=TOKEN_HASH

Registers a new OpenVPN client on the server with the given client name and static VPN IP address (stored in /ccd). If you need an unsigned client that can access VPN without CA passphrase, add `nopass` to the query: */cert?name=CLIENT_NAME&ip?STATIC_VPN_IP&token=TOKEN_HASH&nopass*.

### GET /cert?name=CLIENT_NAME&token=TOKEN_HASH

Retrieves **ovpn** file that can be sent to the client.

### DELETE /cert?name=CLIENT_NAME&token=TOKEN_HASH

Unregisters the client and removes their certificates, keys and CCD entry.

### GET /cert/ccd?token=TOKEN_HASH

Prints the content of the CCD folder, with filenames and their content (to pair client names with their static VPN IPs).