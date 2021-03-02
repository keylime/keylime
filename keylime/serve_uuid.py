'''
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
'''

from http.server import BaseHTTPRequestHandler, HTTPServer

import sys
import uuid

import json


TESTING_MODE = False

if not TESTING_MODE:
    from keylime.cmd import provider_vtpm_add


class myHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        if TESTING_MODE:
            myUUID = str(uuid.uuid4())
        else:
            myUUID = provider_vtpm_add.add_vtpm("current_group.tpm")
        self.request.sendall(json.dumps({'uuid': myUUID}))


try:
    port_number = None
    if (len(sys.argv) < 2 and not TESTING_MODE):
        print("Requests vtpm uuid from vtpm manager")
        print("Usage: serve_uuid.py port_number")
        sys.exit(-1)
    else:
        port_number = int(sys.argv[1])

    server = HTTPServer(('', port_number), myHandler)
    print('Started httpserver on port ', port_number)

    server.serve_forever()

except KeyboardInterrupt:
    print('^C received, shutting down the server')
    server.socket.close()
