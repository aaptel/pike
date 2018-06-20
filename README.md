Pike
====

Pike is a (nearly) pure-Python framework for writing SMB2/3 protocol correctness tests.
See [LICENSE](LICENSE) for licensing information.

There is also [API documentation from epydoc](http://emc-isilon.github.io/pike/api/index.html).

Prerequisites
=============

Required for basic functionality:
* Python 2.7
* PyCryptodomex

Required for building kerberos library:
* Python development headers
* MIT gssapi\_krb5 (plus devel headers)
    * Ubuntu: krb5-user, libkrb5-dev

Optional: epydoc for doc generation

Build instructions
==================

Ubuntu 14.04 / 16.04

    apt-get install -y --no-install-recommends krb5-user libkrb5-dev python-dev build-essential python2.7 python-pip
    pip install setuptools pycryptodomex
    python setup.py install

Running POSIX tests
===================

Create /tmp/share:

    mkdir /tmp/share

Set your samba smb.conf to:

    [global]
    server max protocol = SMB3_11
    unix extensions = yes
    
    [share]
    create mask = 07777
    directory mask = 07777
    mangled names = no
    path = /tmp/share
    read only = no
    guest ok = yes

- Edit test.sh with your server info.
- Empty the content of the share and run test.sh

    # run all POSIX tests
    rm -rf /tmp/share/* ; ./test.sh

    # run a single test (look in pike/test/posixext.py for names)
    rm -rf /tmp/share/* ; ./test.sh POSIXTest.test_reserved_char


Running tests
=============

The tests in the test subdirectory are ordinary Python unittest tests and
can be run as usual.  The following environment variables are used by
the tests:

    PIKE_SERVER=<host name or address>
    PIKE_SHARE=<share name>
    PIKE_CREDS=DOMAIN\User%Passwd
    PIKE_LOGLEVEL=info|warning|error|critical|debug
    PIKE_SIGN=yes|no
    PIKE_ENCRYPT=yes|no
    PIKE_MAX_DIALECT=DIALECT_SMBX_Y_Z
    PIKE_MIN_DIALECT=DIALECT_SMBX_Y_Z
    PIKE_TRACE=yes|no

If PIKE\_TRACE is set to "yes", then incoming/outgoing packets
will be logged at debug level.

    $ python -m unittest discover -s pike/test -p *.py

Alternatively, to build and run all tests

    $ python setup.py test

To run an individual test file:

    $ python -m unittest discover -s pike/test -p echo.py EchoTest.test_echo

Kerberos Hints
==============

Setting up MIT Kerberos as provided by many linux distributions to interop
with an existing Active Directory and Pike is relatively simple.

If PIKE\_CREDS is not specified and the kerberos module was built while
installing pike, your current Kerberos credentials will be used to
authenticate.

Use a minimal /etc/krb5.conf on the client such as the following

    [libdefaults]
        default_realm = AD.EXAMPLE.COM

Retrieve a ticket for the desired user

    $ kinit user_1

(Optional) in leiu of DNS, add host entries for the server name + domain

    $ echo "10.1.1.150    smb-server.ad.example.com" >> /etc/hosts

Fire pike tests

    $ PIKE_SERVER="smb-server.ad.example.com" PIKE_SHARE="C$" python -m unittest discover -s pike/test -p tree.py

Note that you will probably need to specify the server by fully-qualified
hostname in order for Kerberos to figure out which ticket to use.  If you
get errors during session setup when using an IP address, this is probably
the reason.
