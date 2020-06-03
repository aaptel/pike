#!/usr/bin/env python3
import re
import subprocess
from pprint import pprint as P
import getpass
import time
import argparse
import signal
import os

# pike stuff
import sys
try:
    import pike
except:
    try:
        sys.path.append(os.path.join(os.path.dirname(__file__)))
        import pike
    except:
        print("cannot import pike: run from pike dir or install pike")
        exit(1)
from pike import model, smb2, ntstatus
import pike


SHARE_ALL = smb2.FILE_SHARE_READ | smb2.FILE_SHARE_WRITE | smb2.FILE_SHARE_DELETE
ACCESS_ALL = smb2.FILE_READ_DATA | smb2.FILE_WRITE_DATA | smb2.DELETE

SERVER = "192.168.2.109"
SHARE  = "data"
CREDS  = 'administrator%aaptel-42'

def main():
    ap = argparse.ArgumentParser(description="oplock trigger helper")
    ap.add_argument("-U", "--credentials", help="login info (USER%%PW)")
    ap.add_argument("-t", "--trace", action='store_true', default=False, help="make tcpdump capture to $PWD/trace.pcap")
    ap.add_argument("UNC", help="server and share to connect to (//<host>/<share>)")
    args = ap.parse_args()
    
    if args.credentials:
        parse_creds(args.credentials)

    parse_unc(args.UNC)
    
    cap = None
    if args.trace:
        if os.path.exists('trace.pcap'):
            os.unlink('trace.pcap')
        cap = subprocess.Popen(['sudo', 'tcpdump', '-s0',
                                '-w', 'trace.pcap', '-Z', getpass.getuser(),
                                'port', '445'])
        time.sleep(1)

    make_oplock('foo.txt')

    if cap:
        time.sleep(1)
        # we can't kill cap.pid directly because it belongs to root (sudo)
        # find tcpdump child and kill that
        pid = int(subprocess.check_output('ps -o pid= --ppid=%d'%cap.pid, shell=True).decode('utf-8'))
        os.kill(pid, signal.SIGINT)
        cap.wait()

def parse_unc(s):
    m = re.match(r'^(?:(?:smb:)?//)?(\S+?)/(\S+)', s)
    if not m:
        die("invalid UNC path <%s>"%s)
    global SERVER
    global SHARE
    SERVER = m.group(1)
    SHARE = m.group(2)
    
def parse_creds(s):
    x = s.split('%', 1)
    if not x or len(x) != 2:
        die("invalid creds <%s>"%s)
    global CREDS
    CREDS = s

def chan_oplock_handler(handle, level):
    print("handle %s got oplock break level %d"%(handle, level))
    return level

def make_oplock(fn):
    client = model.Client(dialects=[smb2.DIALECT_SMB3_0])
    conn = client.connect(SERVER, 445)
    conn.negotiate()
    chan = conn.session_setup(CREDS)
    tree = chan.tree_connect(SHARE)

    info('open#1 %s...'%fn)
    handle1 = chan.create(tree,
                          fn,
                          share=SHARE_ALL,
                          oplock_level=pike.smb2.SMB2_OPLOCK_LEVEL_EXCLUSIVE).result()
    
    handle1.on_oplock_break(lambda level: chan_oplock_handler(handle1, level))
    
    info('open#2 %s...'%fn)
    handle2 = chan.create(tree,
                          fn,
                          share=SHARE_ALL,
                          oplock_level=pike.smb2.SMB2_OPLOCK_LEVEL_II).result()
    
    info('close#1 %s...'%fn)
    chan.close(handle1)
    info('close#2 %s...'%fn)
    chan.close(handle2)

def info(s):
    print(s)

def die(s):
    print(s, file=sys.stderr)
    exit(1)

if __name__ == '__main__':
    main()
