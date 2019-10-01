'''
DISTRIBUTION STATEMENT A. Approved for public release: distribution unlimited.

This material is based upon work supported by the Assistant Secretary of Defense for
Research and Engineering under Air Force Contract No. FA8721-05-C-0002 and/or
FA8702-15-D-0001. Any opinions, findings, conclusions or recommendations expressed in this
material are those of the author(s) and do not necessarily reflect the views of the
Assistant Secretary of Defense for Research and Engineering.

Copyright 2016 Massachusetts Institute of Technology.

The software/firmware is provided to you on an As-Is basis

Delivered to the US Government with Unlimited Rights, as defined in DFARS Part
252.227-7013 or 7014 (Feb 2014). Notwithstanding any copyright notice, U.S. Government
rights in this work are defined by DFARS 252.227-7013 or DFARS 252.227-7014 as detailed
above. Use of this work other than as specifically authorized by the U.S. Government may
violate any copyrights that exist in this work.
'''

from http.server import BaseHTTPRequestHandler, HTTPServer

import sys
import uuid

try:
    import simplejson as json
except ImportError:
    raise("Simplejson is mandatory, please install")

TESTING_MODE = False

if not TESTING_MODE:
    from keylime import provider_vtpm_add

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
        return

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
