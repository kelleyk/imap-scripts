from __future__ import absolute_import, unicode_literals, division, print_function

from sqlalchemy import Column, ForeignKey, Index, Integer, LargeBinary, String, Table, Text, Enum, UnicodeText
from sqlalchemy import create_engine, and_
from sqlalchemy.orm import relationship
from sqlalchemy.orm.exc import MultipleResultsFound, NoResultFound
from sqlalchemy.orm.session import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

from .util import get_addresses_from_header


Base = declarative_base()
metadata = Base.metadata


def open_db(path):
    """Returns a SQLite DB session."""
    sql_engine = create_engine('sqlite:///' + path)

    if not sql_engine.dialect.has_table(sql_engine, 'message'):
        metadata.create_all(bind=sql_engine)
    
    DBSession = sessionmaker(bind=sql_engine)
    return DBSession()


class Message(Base):
    __tablename__ = 'message'
    
    # This is the UID from IMAP.
    uid = Column(Integer, primary_key=True, unique=True, nullable=False)

    header_auto_submitted = Column(UnicodeText, nullable=True)
    header_list_unsubscribe = Column(UnicodeText, nullable=True)
    

class Address(Base):
    """An address is a (name, email) 2-tuple."""

    __tablename__ = 'address'
    
    # This is an arbitrary identifier that we assign.
    aid = Column(Integer, primary_key=True, unique=True, nullable=False)

    name = Column(UnicodeText, nullable=False)
    email_addr = Column(UnicodeText, nullable=False)

    __table_args__ = (
        Index('name_email_idx', 'name', 'email_addr', unique=True),
    )

    def as_tuple(self):
        return (self.name, self.email_addr)

    
class MessageAddress(Base):
    __tablename__ = 'message_address_join'

    uid = Column(Integer, ForeignKey('message.uid'), index=True, nullable=False, primary_key=True)
    aid = Column(Integer, ForeignKey('address.aid'), index=True, nullable=False, primary_key=True)
    kind = Column(Enum('FROM', 'TO', 'CC', 'BCC'), nullable=False, primary_key=True)

    message = relationship('Message', backref='message_addresses')
    address = relationship('Address', backref='message_addresses')


def populate_message(db, uid, imap_msg):
    db_msg = Message(uid=uid)
    db.add(db_msg)

    db_msg.header_auto_submitted = '\n'.join(imap_msg.get_all('Auto-Submitted', ()))
    db_msg.header_list_unsubscribe = '\n'.join(imap_msg.get_all('List-Unsubscribe', ()))
    
    for kind in ('From', 'To', 'Cc', 'Bcc'):
        for addr in get_addresses_from_header(imap_msg, kind):
            db_addr = get_address(db, addr)
            db.add(MessageAddress(message=db_msg, address=db_addr, kind=kind.upper()))

    return db_msg
        

def get_address(db, addr):
    name, email_addr = addr
    try:
        return db.query(Address).filter(and_(Address.name == name, Address.email_addr == email_addr)).one()
    except NoResultFound:
        db_addr = Address(name=name, email_addr=email_addr)
        db.add(db_addr)
        return db_addr

        
