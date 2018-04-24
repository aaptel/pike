import pike.model
import pike.smb2
import pike.test
import sys
import time

if len(sys.argv) != 5:
    print("Usage: %s SERVER SHARE USER%%PW"%sys.argv[0])
    exit(1)

server, share, creds, strtime = sys.argv[1:]

client = pike.model.Client([pike.smb2.DIALECT_SMB2_002])

print("connecting")
conn = pike.model.Connection(client, server)

print("negprot")
conn.negotiate()
print("sess setup")
chan = conn.session_setup(creds)
print("tcon")
tree = chan.tree_connect(share)


print("write file")
share_all = pike.smb2.FILE_SHARE_READ | pike.smb2.FILE_SHARE_WRITE | pike.smb2.FILE_SHARE_DELETE
file = chan.create(tree,
                   'testfile.txt',
                   access=pike.smb2.FILE_READ_DATA | pike.smb2.FILE_WRITE_DATA | pike.smb2.DELETE,
                   share=share_all,
                   disposition=pike.smb2.FILE_SUPERSEDE,
                   options=pike.smb2.FILE_DELETE_ON_CLOSE,
                   oplock_level=pike.smb2.SMB2_OPLOCK_LEVEL_EXCLUSIVE).result()
chan.write(file, 0, "contents");
chan.close(file);

print("tdis")
chan.tree_disconnect(tree)

print("logoff")
chan.logoff()
print("waiting before doing ses setup again...")
ftime = float(strtime)
time.sleep(ftime)

print("sess setup")
chan = conn.session_setup(creds)
print("tcon")
tree = chan.tree_connect(share)


print("write file")
share_all = pike.smb2.FILE_SHARE_READ | pike.smb2.FILE_SHARE_WRITE | pike.smb2.FILE_SHARE_DELETE
file = chan.create(tree,
                   'testfile.txt',
                   access=pike.smb2.FILE_READ_DATA | pike.smb2.FILE_WRITE_DATA | pike.smb2.DELETE,
                   share=share_all,
                   disposition=pike.smb2.FILE_SUPERSEDE,
                   options=pike.smb2.FILE_DELETE_ON_CLOSE,
                   oplock_level=pike.smb2.SMB2_OPLOCK_LEVEL_EXCLUSIVE).result()
chan.write(file, 0, "contents");
chan.close(file);

print("tdis")
chan.tree_disconnect(tree)

print("logoff")
chan.logoff()

print("done")
