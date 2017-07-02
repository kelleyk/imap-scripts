from __future__ import absolute_import, unicode_literals, division, print_function
"""Scrape contacts from a Google email account.

Usage:
- First, you need an OAuth2 access token.  Run e.g.
  $ python2 oauth.py --client_id="..." --client_secret="..." --user=jdoe@example.com --generate_oauth2_token
- Open the URL in a web browser, log in as normal, and then copy and paste the code you're given in the script window.
  You will get, among other things, an access token.
- Run e.g.
  $ imap-get-correspondents --username=jdoe@example.com --access-token="..."

Features:
- Caches message information in a local SQLite database so that the program can be restarted if it exits and so that
  subsequent runs of the program do not have to start from the beginning; only new messages will need to be processed.
- Detection of automated messages (by headers).
- Detection of mailing list messages (by headers).
- Heuristic detection of addresses that "look automated" based on the local or domain parts of the email address.
- Heuristic for selecting a name when multiple names have been seen associated with a single email address.

Implementation notes:
- We can't directly connect to Google's IMAP servers with a username and password unless we enable "access from
  less-secure applications".  Instead,  we need to use the "OAuth2 for Installed Applications" flow:
  https://developers.google.com/identity/protocols/OAuth2InstalledApp
"""


import sys
import imaplib
import argparse
import email
import email.header

from .util import build_xoauth2_auth_string, is_automated, merge_addresses
from .models import open_db, populate_message, Message


PY2 = sys.version_info < (3,)
if PY2:
    text_type = unicode
    binary_type = str
else:
    text_type = str
    binary_type = bytes

    
GMAIL_ALL_MAIL = '"[Gmail]/All Mail"'


if PY2:
    raise Exception('Has not been tested with Python 2!')


class ImapConnection(object):
    def __init__(self, auth_string, debug=False):
        self.auth_string = auth_string
        self.debug = debug
        self.imap_conn = None
        
    def connect(self):
        imap_conn = imaplib.IMAP4_SSL('imap.gmail.com')
        if self.debug:
            imap_conn.debug = 4
        imap_conn.authenticate('XOAUTH2', lambda x: self.auth_string)
        self.imap_conn = imap_conn

    # Returns strings like
    #   (\All \HasNoChildren) "/" "[Gmail]/All Mail"
    # (We aren't fully parsing the result.)
    def iter_directories(self):
        rt, rval = self.imap_conn.list()
        assert rt == 'OK'  # "response type"; usually "OK" or "NO"
        for s in rval:
            yield s.decode('utf-8')

    # Yields (uid, msg) pairs.
    def iter_messages(self, dir_name=None, limit=None):
        for i, uid in enumerate(self.iter_uids(dir_name=dir_name)):
            if limit is not None and i >= limit:
                break
            yield (uid, self.fetch_message(uid=uid))

    def iter_uids(self, dir_name=None):
        self.imap_conn.select(dir_name)

        rt, rval = self.imap_conn.uid('SEARCH', None, '(ALL)')
        assert rt == 'OK'
        assert len(rval) == 1
        for s in rval[0].decode('utf-8').split():
            yield int(s)
            
    def fetch_message(self, uid):
        assert isinstance(uid, int)

        rt, rval = self.imap_conn.uid('FETCH', text_type(uid), '(BODY.PEEK[])')
        assert rt == 'OK'
        
        if rval[0] is None:
            raise KeyError('No message with UID {}'.format(uid))
        
        return email.message_from_bytes(rval[0][1])  # `policy` arg


def build_parser():
    p = argparse.ArgumentParser()
    p.add_argument('--username', help='e.g. jdoe@gmail.com')
    p.add_argument('--access-token')
    return p


def imap_connect(args):
    c = ImapConnection(
        auth_string=build_xoauth2_auth_string(args.username, args.access_token),
        debug=True,
    )
    c.connect()
    return c


def main_get_correspondents():
    args = build_parser().parse_args()
    c = imap_connect(args)
    
    db = open_db('./correspondents.db')

    # Pull all of the data that we will need into our local cache.  We deliberately defer filtering or cleaning up data
    # so that we have the original data; that way we can tweak filters/etc. locally.
    #
    # N.B.: This use of UIDs is probably fine for my purposes, but there are a lot of tricky, sharp edges around IMAP
    # UIDs!  Ref.: https://www.limilabs.com/blog/unique-id-in-imap-protocol
    for uid in c.iter_uids(GMAIL_ALL_MAIL):
        try:
            # Have we already inspected this message?
            db_msg = db.query(Message).get(uid)
            if db_msg is None:
                print('Need to fetch message UID=={}'.format(uid))
                imap_msg = c.fetch_message(uid)
                db_msg = populate_message(db, uid, imap_msg)
        except:
            db.rollback()
            raise
        else:
            db.commit()

    # Merge all of the data in the local cache, apply our filters/data-scrubbing/heuristics/etc., and produce our
    # result.
    correspondents = set()
    for db_msg in db.query(Message).all():
        
        # https://www.iana.org/assignments/auto-submitted-keywords/auto-submitted-keywords.xhtml
        if db_msg.header_auto_submitted is not None and db_msg.header_auto_submitted.lower().startswith('auto-'):
            print('** ignoring message with Auto-Submitted header')
            continue

        # https://www.ietf.org/rfc/rfc2369.txt
        if db_msg.header_list_unsubscribe is not None and db_msg.header_list_unsubscribe != '':
            print('** ignoring message with List-Unsubscribe header')
            continue

        # Discard individual automated senders.
        for msg_addr in db_msg.message_addresses:
            addr = msg_addr.address.as_tuple()
            if is_automated(addr):
                print('** ignoring address that looks automated: {}'.format(addr))
                continue
            correspondents.add(addr)

    # Display our list!
    for name, email_addr in sorted(merge_addresses(correspondents)):
        print((name, email_addr))
