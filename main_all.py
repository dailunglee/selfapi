from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, ForeignKey
from sqlalchemy import Integer, String, DATETIME, TEXT
from sqlalchemy.orm import sessionmaker, relationship, backref

mode = 0
if mode == 1:
    print("真資料")
else : 
    Base = declarative_base()
    engine_url = "sqlite:///all_schema_data.db"
    engine = create_engine(engine_url)#, echo=True)
    
class GeoIP(Base):
    __tablename__ = "geoip"
    id = Column(Integer, primary_key=True, autoincrement=True)
    ip = Column(String(100))
    lat = Column(String(100)) #float
    lng = Column(String(100)) #float
    size = Column(String(100))# int

class Checkpoint(Base):
    __tablename__ = "checkpoint"
    id = Column(Integer, primary_key=True, autoincrement=True)
    link_id = Column(Integer)
    first_date = Column(String(100))
    last_modified = Column(String(100))
    ioc = Column(String(100))
    ip = Column(String(100))
    port = Column(String(100))
    jarm = Column(String(100))
    jarm_type = Column(String(100))
    #scan_result = Column(String(100))
    
class WordLinkcp(Base):
    __tablename__ = "wordlinkcp"
    id = Column(Integer,primary_key = True)
    #product_id_link = Column(Integer,ForeignKey('product.id'))
    description = Column(String(100))
    link = Column(String(100))
    checkpoint_id_link = Column(Integer, ForeignKey('checkpoint.id'))
    checkpoint = relationship(Checkpoint, backref=backref('wordlinkcp', uselist=True))
    
class DomainName(Base):
    __tablename__ = "domainname"
    id = Column(Integer, primary_key=True, autoincrement=True)
    link_id = Column(Integer)
    first_seen = Column(String(100))
    last_seen = Column(String(100))
    port = Column(String(100))
    country = Column(String(100))
    group = Column(String(100))
    valid_date = Column(String(100))

    
class WordLinkdn(Base):
    __tablename__ = "wordlinkdn"
    id = Column(Integer,primary_key = True)
    wordlinktype = Column(String(100))
    description = Column(String(100))
    link = Column(String(100))
    domainname_id_link = Column(Integer, ForeignKey('domainname.id'))
    domainname = relationship(DomainName, backref=backref('wordlinkdn', uselist=True))
    
class Ioc(Base):
    __tablename__ = "ioc"
    id = Column(Integer, primary_key=True, autoincrement=True)
    link_id = Column(Integer)
    date = Column(String(100))
    last_modified = Column(String(100))
    dn = Column(String(100))
    factor_1 = Column(String(100))
    factor_2 = Column(String(100))
    factor_3= Column(String(100))
    factor_4 = Column(String(100))
    factor_5 = Column(String(100))
    sum = Column(String(100))

    
class WordLinkio(Base):
    __tablename__ = "wordlinkio"
    id = Column(Integer,primary_key = True)
    #product_id_link = Column(Integer,ForeignKey('product.id'))
    description = Column(String(100))
    link = Column(String(100))
    ioc_id_link = Column(Integer, ForeignKey('ioc.id'))
    ioc = relationship(Ioc, backref=backref('wordlinkio', uselist=True))
    
class Threat(Base):
    __tablename__ = "threat"
    id = Column(Integer, primary_key=True, autoincrement=True)
    link_id = Column(Integer)
    published_date = Column(String(100))
    last_modified = Column(String(100))
    cvss = Column(String(100))
    cve = Column(String(100))
    vulnerability_name = Column(String(100))
    other = Column(String(100))
    
    
class WordLinkth(Base):
    __tablename__ = "wordlinkth"
    id = Column(Integer,primary_key = True)
    wordlinktype = Column(String(100))
    description = Column(String(100))
    link = Column(String(100))
    threat_id_link = Column(Integer, ForeignKey('threat.id'))
    threat = relationship(Threat, backref=backref('wordlinkth', uselist=True))
    
    
class VictimDevice(Base):
    __tablename__ = "victimdevice"
    id = Column(Integer, primary_key=True, autoincrement=True)
    link_id = Column(Integer)
    ip = Column(String(100))
    country = Column(String(100))
    vul_type = Column(String(100))
    cvss = Column(String(100))
    cve = Column(String(100))
    add_date = Column(String(100))

    
class WordLinkvd(Base):
    __tablename__ = "wordlinkvd"
    id = Column(Integer,primary_key = True)
    description = Column(String(100))
    link = Column(String(100))
    victimdevice_id_link = Column(Integer, ForeignKey('victimdevice.id'))
    victimdevice = relationship(VictimDevice, backref=backref('wordlinkvd', uselist=True))
    
    
class HackInfo(Base):
    __tablename__ = "hackinfo"
    id = Column(Integer, primary_key=True, autoincrement=True)
    link_id = Column(Integer)
    ip = Column(String(100))
    vul_type = Column(String(100))
    cvss = Column(String(100))
    cve = Column(String(100))

    
class WordLinkhi(Base):
    __tablename__ = "wordlink"
    id = Column(Integer,primary_key = True)
    description = Column(String(100))
    link = Column(String(100))
    hackinfo_id_link = Column(Integer, ForeignKey('hackinfo.id'))
    hackinfo = relationship(HackInfo, backref=backref('wordlinkhi', uselist=True))

class DataExport(Base):
    __tablename__ = "dataexport_name"
    id = Column(Integer, primary_key=True, autoincrement=True)
    probe_time = Column(String(100))
    c2_ip = Column(String(100))
    country = Column(String(100))
    c2_type = Column(String(100))
    domain_name = Column(String(100))
    
class Product(Base):
    __tablename__ = "product"
    id = Column(Integer, primary_key=True, autoincrement=True)
    product_id = Column(String(100))
    product_name = Column(String(100))
    version = Column(String(100))
    vendor = Column(String(100))
    add_datetime = Column(String(100))
    #image = relationship("ImageLink",backref='product')
    
class ImageLinkpro(Base):
    __tablename__ = "imagelinkpro"
    id = Column(Integer,primary_key = True)
    img_src = Column(String(100))
    link = Column(String(100))
    product_id_link = Column(Integer, ForeignKey('product.id'))
    product = relationship(Product, backref=backref('imagelinkpro', uselist=True))

class Exploit(Base):
    __tablename__ = "exploit_name"
    id = Column(Integer, primary_key=True, autoincrement=True)
    date = Column(String(100))
    v = Column(String(100))
    title = Column(String(100))
    type = Column(String(100))
    platform = Column(String(100))
    author = Column(String(100))

class PortActivity(Base):
    __tablename__ = "portactivity"
    id = Column(Integer, primary_key=True, autoincrement=True)
    create_time = Column(String(100))
    ip = Column(String(100))
    dns_set = Column(String(100))
    port_type = Column(String(100))
    ports = Column(String(100))
    add_ports = Column(String(100))
    delete_ports = Column(String(100))
    
class Apt(Base):
    __tablename__ = "apt"
    id = Column(Integer, primary_key=True, autoincrement=True)
    first_seen = Column(String(100))
    last_seen = Column(String(100))
    domain_name = Column(String(100))
    ip = Column(String(100))
    ports = Column(String(100))
    country = Column(String(100))
    group = Column(String(100))
    activity_type = Column(String(100))
    



def create_table():
    Base.metadata.create_all(engine)


def drop_table():
    Base.metadata.drop_all(engine)


def create_session():
    Session = sessionmaker(bind=engine)
    session = Session()

    return session
    

if __name__ == "__main__":
    drop_table()
    create_table()