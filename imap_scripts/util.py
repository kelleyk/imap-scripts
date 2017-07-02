from __future__ import absolute_import, unicode_literals, division, print_function

import itertools
import email.utils
from collections import defaultdict

iterchain = itertools.chain.from_iterable


def build_xoauth2_auth_string(username, access_token):
    """Returns the SASL argument for the OAuth2 mechanism.

    The result is not base64-encoded.
    """
    return b'user=' + username.encode('utf-8') + b'\1auth=Bearer ' + access_token.encode('utf-8') + b'\1\1'


def get_addresses_from_header(message, header_name):
    # This is an iterable containing 2-tuples of (name, email).
    for name, email_addr in email.utils.getaddresses(h for h in message.get_all(header_name, ())):
        yield name, email_addr


def is_automated(addr):
    name, email_addr = addr
    email_addr = email_addr.lower()
    try:
        local_part, domain_part = email_addr.split('@')
    except:
        # It's perfectly possible to have things that aren't valid email addresses in headers; sigh.
        return False

    if email_addr in (
            'drive-shares-noreply@google.com',
            'webpaynotice.web@paylocity.com',
            'meet@kernel.co',
            'zoomroom@kernel.co',
            'wrike@wrike.com',
            'dse@docusign.net',
            'airtableteam@airtable.com',
            # ...
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
        if len(names) > 1:
            # Sometimes emails seem to wind up in the name field.  If there are names that don't have @ in them, let's
            # prefer those.
            names_not_emails = {s for s in names if '@' not in s}
            if len(names_not_emails) > 0:
                names = names_not_emails
            
        if len(names) == 0:
            yield ('', email_addr)
        else:
            yield (next(iter(names)), email_addr)

            
