import unittest
from pike import model, smb2, test, ntstatus
from pprint import pprint as P

SHARE_ALL = smb2.FILE_SHARE_READ | smb2.FILE_SHARE_WRITE | smb2.FILE_SHARE_DELETE
ACCESS_ALL = smb2.FILE_READ_DATA | smb2.FILE_WRITE_DATA | smb2.DELETE

BASEDIR = 'posix_test'

def get_posix_cc(resp):
    for cc in resp.create_response:
        if isinstance(cc, smb2.POSIXResponse):
            return cc
    return None

class POSIXTest(test.PikeTest):

    def test_reserved_char(self):
        perms = 0o644
        names = [
            'a ',
            'a  ',
            '. ',
            '.  ',
            'a.',
            '.a',
            ':',
            ' :: ',
            '\\',
            ' \\ ',
            '>',
            '<'
            '?',
            '\\:*<>?. ',
        ]

        self.negotiate()

        for fn in names:
            f = self.chan.create(self.tree,
                                 fn,
                                 access=ACCESS_ALL,
                                 share=SHARE_ALL,
                                 disposition=smb2.FILE_SUPERSEDE,
                                 posix_perms=perms).result()
            self.chan.close(f)

        err = 0
        r = self.list_dir("")
        for fn in names:
            if unicode(fn) not in r:
                print("file with reserved char <%s> not listed")
                err += 1

        self.assertTrue(err == 0)

    def test_case_sensitive(self):
        self.negotiate()
        requested_perms = 0o644
        print("creating file 'a'")
        handle = self.chan.create(self.tree,
                                  'a',
                                  access=ACCESS_ALL,
                                  share=SHARE_ALL,
                                  disposition=smb2.FILE_CREATE,
                                  posix_perms=requested_perms).result()
        self.chan.close(handle)

        print("opening file 'A'")
        open_failed = False
        try:
            handle = self.chan.create(self.tree,
                                      'A',
                                      access=ACCESS_ALL,
                                      share=SHARE_ALL,
                                      disposition=smb2.FILE_OPEN,
                                      posix_perms=requested_perms).result()
        except Exception as e:
            print(e)
            open_failed = True

        self.assertTrue(open_failed, "opening uppercase file didnt fail")

    def test_perm_dirs(self):
        urx = 0o500
        setid = 0o6000
        files = {}

        self.negotiate()

        for requested_perms in range(0o7777+1):

            if requested_perms & urx != urx or requested_perms & setid != 0:
                #print("skipping perms %04o (mising u=rx)"%requested_perms)
                continue

            fn = 'testdir%04o' % requested_perms
            files[fn] = requested_perms
            #print("creating dir with perm %04o"%requested_perms)
            handle = self.chan.create(self.tree,
                                      fn,
                                      access=ACCESS_ALL,
                                      share=SHARE_ALL,
                                      disposition=smb2.FILE_CREATE,
                                      options=smb2.FILE_DIRECTORY_FILE,
                                      posix_perms=requested_perms).result()
            self.chan.close(handle)

        # check permissions via querydirectoryinfo
        err = 0
        r = self.list_dir("")
        for fn, req in files.items():
            rsp = r[unicode(fn)].perms
            if req != rsp:
                print("asked %04o, got %04o back"%(req, rsp))
                err += 1
        self.assertTrue(err == 0)

    def test_perm_files(self):
        files = {}

        self.negotiate()

        for requested_perms in range(0o7777+1):
            fn = 'testfiles%04o' % requested_perms
            files[fn] = requested_perms
            #print("creating file with perm %04o"%requested_perms)
            handle = self.chan.create(self.tree,
                                      fn,
                                      access=ACCESS_ALL,
                                      share=SHARE_ALL,
                                      disposition=smb2.FILE_CREATE,
                                      posix_perms=requested_perms).result()
            self.chan.close(handle)

        # check permissions via querydirectoryinfo
        r = self.list_dir("")
        err = 0
        for fn, req in files.items():
            rsp = r[unicode(fn)].perms
            if req != rsp:
                print("asked %04o, got %04o back"%(req, rsp))
                err += 1
        self.assertTrue(err == 0)

    def list_dir(self, path):
        d = self.chan.create(self.tree,
                             path,
                             access=ACCESS_ALL,
                             attributes=smb2.FILE_ATTRIBUTE_DIRECTORY,
                             share=SHARE_ALL,
                             options=smb2.FILE_DIRECTORY_FILE,
                             posix_perms=0o744).result()
        x = self.chan.enum_directory(d, file_information_class=smb2.FILE_POSIX_INFORMATION)
        r = {}
        for f in x:
            assert f.file_name not in r
            r[f.file_name] = f

        self.chan.close(d)
        return r

    def delete_file(self, fn, perms=0):
        f = self.chan.create(self.tree,
                             fn,
                             access=ACCESS_ALL,
                             share=SHARE_ALL,
                             disposition=smb2.FILE_OPEN,
                             options=smb2.FILE_DELETE_ON_CLOSE,
                             posix_perms=perms).result()
        self.chan.close(f)

    def negotiate(self, *args, **kwds):
        self.client = model.Client(dialects=[smb2.DIALECT_SMB3_1_1])
        self.conn = self.client.connect(self.server, self.port)
        kwds['posix'] = True
        resp = self.conn.negotiate(*args, **kwds).negotiate_response
        if resp.dialect_revision < smb2.DIALECT_SMB3_1_1:
            self.skipTest("SMB3.1.1 required")
        if smb2.SMB2_POSIX_CAPABILITIES not in [ctx.context_type for ctx in resp]            :
            self.skipTest("Server does not support POSIX extensions")
        self.chan = self.conn.session_setup(self.creds)
        self.tree = self.chan.tree_connect(self.share)

if __name__ == '__main__':
    unittest.main()
