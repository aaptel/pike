import pike.model
import pike.smb2
import pike.test
import sys
import time

if len(sys.argv) != 4:
    print("Usage: %s SERVER SHARE USER%%PW"%sys.argv[0])
    exit(1)

server, share, creds = sys.argv[1:]

client = pike.model.Client([pike.smb2.DIALECT_SMB2_1])

print("connecting")
conn = pike.model.Connection(client, server)

print("negprot")
conn.negotiate()
print("sess setup")
chan = conn.session_setup(creds)
print("logoff")
chan.logoff()
print("waiting before doing ses setup again...")
time.sleep(3)

print("sess setup")
chan = conn.session_setup(creds)
chan.logoff()

print("done")
