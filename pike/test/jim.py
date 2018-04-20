# Module Name:
#
#        jim.py
#
# Abstract:
#
#        Test a Session setup after a logoff on the same socket
#
# Authors: aaptel
#          palcantara
#

import pike.model
import pike.smb2
import pike.test

class JimTest(pike.test.PikeTest):
    def test_jim(self):
        client = pike.model.Client([pike.smb2.DIALECT_SMB2_1])
        conn = pike.model.Connection(client, "foo.com")

        conn.negotiate()
        chan = conn.session_setup("FOO\\aaptel%aaptel")
        chan.logoff()
        chan = conn.session_setup("FOO\\aaptel%aaptel")
        chan.logoff()
