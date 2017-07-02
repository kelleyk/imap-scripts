from __future__ import absolute_import, unicode_literals, division, print_function
"""
Scrape contacts from a Google email account.

Implementation notes:
- We can't directly connect to Google's IMAP servers with a username and password unless we enable "access from
  less-secure applications".
- We need to use the "OAuth2 for Installed Applications" flow:
  https://developers.google.com/identity/protocols/OAuth2InstalledApp
"""


import sys
import base64
import imaplib
import argparse
import itertools
import email
import email.header
from collections import defaultdict


PY2 = sys.version_info < (3,)
if PY2:
    text_type = unicode
    binary_type = str
else:
    text_type = str
    binary_type = bytes

    
iterchain = itertools.chain.from_iterable
    
    
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


def build_xoauth2_auth_string(username, access_token):
    """Returns the SASL argument for the OAuth2 mechanism.

    The result is not base64-encoded.
    """
    return b'user=' + username.encode('utf-8') + b'\1auth=Bearer ' + access_token.encode('utf-8') + b'\1\1'


def get_addresses_from_header(message, header_name):
    # This is an iterable containing 2-tuples of (name, email).
    for name, email_addr in email.utils.getaddresses(h for h in message.get_all(header_name, ())):
        yield name, email_addr


def get_addresses(message):
    addrs = set(iterchain(get_addresses_from_header(message, h) for h in ('To', 'Cc', 'Bcc')))
    addrs.update(a for a in get_addresses_from_header(message, 'From') if not automated(a))
    return addrs


def build_parser():
    p = argparse.ArgumentParser()
    p.add_argument('--username', help='e.g. jdoe@gmail.com')
    p.add_argument('--access-token')
    return p


def automated(addr):
    name, email_addr = addr
    email_addr = email_addr.lower()
    local_part, domain_part = email_addr.split('@')

    if email_addr in (
            'drive-shares-noreply@google.com',
            'webpaynotice.web@paylocity.com',
            'meet@kernel.co',
            'zoomroom@kernel.co',
            'wrike@wrike.com',
    ):
        return True

    if local_part.endswith('+noreply') or local_part.startswith('support+'):
        return True
    if local_part in ('noreply', 'no-reply', 'donotreply', 'automated', 'support', 'help', 'info', 'sales'):
        return True
    if domain_part in ('docs.google.com', 'resource.calendar.google.com'):
        return True

    return False


def is_list_post(msg):
    return (len(msg.get_all('List-Post', [])) > 0)


def merge_addresses(addrs):
    """Merges addresses with matching emails.

    Takes an iterable of (name, email) 2-tuples; emails are lowercased and then a single name is picked for each unique
    email address.  Returns an iterable of 2-tuples."""
    
    names_by_email = defaultdict(set)
    for name, email_addr in addrs:
        names_by_email[email_addr.lower()].add(name)

    for email_addr, names in names_by_email.items():
        names = {s.strip() for s in names}
        names = {s for s in names if s != ''}
        if len(names) > 0:
            import pdb; pdb.set_trace()
            
        if len(names) == 0:
            yield ('', email_addr)
        else:
            yield (next(iter(names)), email_addr)
            

def main_get_correspondents():
    args = build_parser().parse_args()

    c = ImapConnection(
        auth_string=build_xoauth2_auth_string(args.username, args.access_token),
        debug=True,
    )
    c.connect()

    correspondents = set()
    for uid, msg in c.iter_messages('"[Gmail]/All Mail"'):
        if not is_list_post(msg):
            correspondents.update(get_addresses(msg))
    for name, email_addr in sorted(merge_addresses(correspondents)):
        print((name, email_addr))
        

# For testing/troubleshooting.
def main_fetch_single():
    args = build_parser().parse_args()
    
    c = ImapConnection(
        auth_string=build_xoauth2_auth_string(args.username, args.access_token),
        debug=True,
    )
    c.connect()
    
    c.imap_conn.select('"[Gmail]/All Mail"')
    msg = c.fetch_message(1155)
    print(msg)
    import pdb; pdb.set_trace()
    
