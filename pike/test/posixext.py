from pike import model, smb2, test, ntstatus

SHARE_ALL = smb2.FILE_SHARE_READ | smb2.FILE_SHARE_WRITE | smb2.FILE_SHARE_DELETE
ACCESS_ALL = smb2.FILE_READ_DATA | smb2.FILE_WRITE_DATA | smb2.DELETE

def get_posix_cc(resp):
    for cc in resp.create_response:
        if isinstance(cc, smb2.POSIXResponse):
            return cc
    return None

class POSIXTest(test.PikeTest):

    def test_posix_create_perms(self):
        resp = self.negotiate()

        for delete_after in [True, False]:
            for requested_perms in range(0o777+1):
                print("creating file with perm %04o"%requested_perms)
                file = self.chan.create(self.tree,
                                        'testfile.txt',
                                        access=ACCESS_ALL,
                                        share=SHARE_ALL,
                                        disposition=smb2.FILE_SUPERSEDE,
                                        options=smb2.FILE_DELETE_ON_CLOSE,
                                        posix_perms=requested_perms).result()
                pcc = get_posix_cc(file)
                self.assertIsNot(pcc, None)
                self.assertEqual(pcc.perms, requested_perms, "request perms %04o but got %04o back"%(requested_perms, pcc.perms))
                self.chan.close(file)
                #self.delete_file('testfile.txt')

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

    def delete_file(self, filename):
        file = self.chan.create(self.tree, filename, access=ACCESS_ALL, share=SHARE_ALL, options=smb2.FILE_DELETE_ON_CLOSE).result()
        self.chan.close(file)
