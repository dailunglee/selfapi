from main_all import create_session
 
from main_all import GeoIP
from main_all import Checkpoint, WordLinkcp
from main_all import DomainName, WordLinkdn
from main_all import Ioc, WordLinkio
from main_all import Threat, WordLinkth
from main_all import VictimDevice, WordLinkvd
from main_all import HackInfo, WordLinkhi
from main_all import DataExport
from main_all import Product, ImageLinkpro
from main_all import Exploit
from main_all import PortActivity
from main_all import Apt


import requests
import json
#from datetime import datetime
from pprint import pprint

geoip = [
        {"ip":"120.66.169.212","lat":47.41322,"lng":-1.219482,"size":1000000},
]

checkpoint = [
    {"link_id":"1","first_date": "2021/8/17 下午 12:20:00","last_modified":"2021/8/17 下午 12:20:00",\
     "ioc":"n/a","ip":"192.15.100.22","port":"443","jarm":"59248c4dae276a021cb296d2ee0e6a0c962a8d7e",\
         "jarm_type":"APT_GROUP","scan_result":[{ "description": "純文字", "link": "/#/", }]},
]

domainname =[
        {"link_id":"1","first_seen":"2021/8/17 下午 12:20:00","last_seen":"2021/8/17 下午 12:22:00",\
         "dn":[{ "description": "example.com", "link": "#", }],"ip":[{ "description": "192.168.0.1", "link": "/#/", }],\
             "port":"[80, 81, 82]","country":"美國","group":"TrendMicro","register_email":\
                 [{"description": "123@example.com","link": "#",}],"valid_date":"2022/12/17",\
                     "report":[{"description": "report","link": "/#/",}]},
]

ioc = [
        {"link_id": 1, "date": "2021/8/17 下午 12:22:00","last_modified":"2021/8/17 下午 12:20:00",\
         "dn":"example.com","ioc_source":[{ "description": "Report", "link": "", }],\
            "factor_1":50,"factor_2":0,"factor_3":0,"factor_4":0,"factor_5":0,"sum":50 },
]

threat = [
        {"link_id": 1, "published_date": "2021/6/13","last_modified":"2021/6/13", \
         "cvss":"7.3","cve":"CVE-2022-1654","vulnerability_name": \
             "Jupiter Theme <= 6.10.1 and JupiterX Core Plugin <= 2.0.7 allow any authenticated attacker",\
                 "effect_software":[{"description": "cpe:2.3:a:artbees:jupiterx:*:*:*:*:*:wordpress:*:*", \
                    "link": "",}],"exploit":[{ "description": "Exploit", "link": "", }],\
                    "other":"n/a","possible_ip":[{ "description": "102", "link": "", }]},
    
]

victimdevice = [
        {"link_id":"1", "ip": "8.123.122.2","country":"美國","vul_type":"RCE",\
         "scan_result":[{"description":"File", "link":""}],"cvss":"7.3",\
             "cve":"CVE-2022-1654","add_date":"2022/6/14"},

]

hackinfo = [
        {"link_id":"1", "ip": "8.123.122.2","vul_type":"RCE","cvss":"7.3",\
         "cve":"CVE-2022-1654","scan_result":[{"description":"File", "link":""}]},

]

dataexport = [
    { "probe_time": "2021/8/17 上午 12:22:00","c2_ip":"192.15.100.22",\
     "country":"美國","c2_type":"APT_N","domain_name":"mefinute.com"},

]

product = [
    {"product_id":"1","product_name":"Windows","version":"2019",\
     "vendor":"Microsoft","add_datetime":"2021/8/17 上午 12:22:00",\
         "image":[ { "img_src": "https://picsum.photos/200/300", "link": "#", },\
                  { "img_src": "https://picsum.photos/200/300", "link": "#", }, ]},
                  
]

exploit = [
    {"date":"2022/6/14","v":"Y","title":"SolarView Compact 6.00 - 'pow' Cross-Site Scripting (XSS) ",\
     "type":"WebApps","platform":"Hardware","author":"Ahmed Alroky "},

]

portactivity = [
    {"create_time":"2021/8/17 下午 8:24:59","ip":"165.160.15.20",\
     "dns_set":"computracenter.com","port_type":"Dynamic","ports":"[22,80]",\
         "add_ports":"[22,443]","delete_ports":"[]"},
]
apt = [
    {"first_seen":"2021/8/17 上午 12:22:00","last_seen":"2021/8/17 上午 12:22:00",\
    "domain_name":"mefminute.com","ip":"192.0.78.25","ports":"[80,443]",\
         "country":"美國","group":"TrendMicro","activity_type":"未知"},
]

for item in geoip:
    data_obj = {
        "ip": item["ip"],
        "lat": item["lat"],
        "lng": item["lng"],
        "size": item["size"],
    }

    session = create_session()
    session.add(GeoIP(**data_obj))
    session.commit()
    session.close()
    
for item in checkpoint:
    data_obj = {
        "link_id": item["link_id"],
        "first_date": item["first_date"],
        "last_modified": item["last_modified"],
        "ioc": item["ioc"],
        "ip": item["ip"],
        "port": item["port"],
        "jarm": item["jarm"],
        "jarm_type": item["jarm_type"],
        #"scan_result": item["scan_result"],
    }

    session = create_session()

    session.add(Checkpoint(**data_obj))
    
    for item1 in item["scan_result"]:
        data_obj1 = {
            "description" : item1["description"],
            "link" : item1["link"],
        }
        word_add = WordLinkcp(**data_obj1)
        id_checkpoint = Checkpoint(link_id = item["link_id"])#使用ip連接wordlink
        word_add.checkpoint = id_checkpoint
        session.add(word_add)
        
    session.commit()
    session.close()
    
for item in domainname:
    data_obj = {
        "link_id": item["link_id"],
        "first_seen": item["first_seen"],
        "last_seen": item["last_seen"],
        #"dn": item["dn"],
        #"ip": item["ip"],
        "port": item["port"],
        "country": item["country"],
        "group": item["group"],
        "valid_date": item["valid_date"],
    }

    session = create_session()

    session.add(DomainName(**data_obj))
    
    for item1 in item["register_email"]: #register_email
        data_obj1 = {
            "wordlinktype" : "register_email",
            "description" : item1["description"],
            "link" : item1["link"],
            
        }

        word_add = WordLinkdn(**data_obj1)
        id_domainname = DomainName(link_id = item["link_id"])#使用id連接wordlink
        word_add.domainname = id_domainname
        session.add(word_add)
     
    for item2 in item["report"]: #report
        data_obj2 = {
            "wordlinktype" : "report",
            "description" : item2["description"],
            "link" : item2["link"],
            
        }

        word_add = WordLinkdn(**data_obj2)
        id_domainname = DomainName(link_id = item["link_id"])#使用id連接wordlink
        word_add.domainname = id_domainname
        session.add(word_add)
        
    for item3 in item["dn"]: #dn
        data_obj3 = {
            "wordlinktype" : "dn",
            "description" : item3["description"],
            "link" : item3["link"],
            
        }

        word_add = WordLinkdn(**data_obj3)
        id_domainname = DomainName(link_id = item["link_id"])#使用id連接wordlink
        word_add.domainname = id_domainname
        session.add(word_add)
        
    for item4 in item["ip"]: #ip
        data_obj4 = {
            "wordlinktype" : "ip",
            "description" : item4["description"],
            "link" : item4["link"],
            
        }

        word_add = WordLinkdn(**data_obj4)
        id_domainname = DomainName(link_id = item["link_id"])#使用id連接wordlink
        word_add.domainname = id_domainname
        session.add(word_add)
    
    
    session.commit()
    session.close()

for item in ioc:
    data_obj = {
        "link_id": item["link_id"],
        "date": item["date"],
        "last_modified": item["last_modified"],
        "dn": item["dn"],
        "factor_1": item["factor_1"],
        "factor_2": item["factor_2"],
        "factor_3": item["factor_3"],
        "factor_4": item["factor_4"],
        "factor_5": item["factor_5"],
        "sum": item["sum"],
    }

    session = create_session()

    session.add(Ioc(**data_obj))
    
    for item1 in item["ioc_source"]:
        data_obj1 = {
            "description" : item1["description"],
            "link" : item1["link"],
            
        }

        word_add = WordLinkio(**data_obj1)
        id_ioc = Ioc(link_id = item["link_id"])#使用id連接wordlink
        word_add.ioc = id_ioc
        session.add(word_add)
    session.commit()
    session.close()
    
    
for item in threat:
    data_obj = {
        "link_id": item["link_id"],
        "published_date": item["published_date"],
        "last_modified": item["last_modified"],
        "cvss": item["cvss"],
        "cve": item["cve"],
        "vulnerability_name": item["vulnerability_name"],
        "other": item["other"],
    }

    session = create_session()

    session.add(Threat(**data_obj))
    
    for item1 in item["effect_software"]: #effect_software
        data_obj1 = {
            "wordlinktype" : "effect_software",
            "description" : item1["description"],
            "link" : item1["link"],
            
        }

        word_add = WordLinkth(**data_obj1)
        id_threat = Threat(link_id = item["link_id"])#使用id連接wordlink
        word_add.threat = id_threat
        session.add(word_add)
    
    for item2 in item["exploit"]:
        data_obj2 = {
            "wordlinktype" : "exploit",
            "description" : item2["description"],
            "link" : item2["link"],
            
        }

        word_add = WordLinkth(**data_obj2)
        id_threat = Threat(link_id = item["link_id"])#使用id連接wordlink
        word_add.threat = id_threat
        session.add(word_add)
        
    for item3 in item["possible_ip"]:
        data_obj3 = {
            "wordlinktype" : "possible_ip",
            "description" : item3["description"],
            "link" : item3["link"],
            
        }

        word_add = WordLinkth(**data_obj3)
        id_threat = Threat(link_id = item["link_id"])#使用id連接wordlink
        word_add.threat = id_threat
        session.add(word_add)
    
    
    session.commit()
    session.close()
    
for item in victimdevice:
    data_obj = {
        "link_id": item["link_id"],
        "ip": item["ip"],
        "country": item["country"],
        "vul_type": item["vul_type"],
        "cvss": item["cvss"],
        "cve": item["cve"],
        "add_date": item["add_date"],
    }

    session = create_session()

    session.add(VictimDevice(**data_obj))
    
    for item1 in item["scan_result"]:
        data_obj1 = {
            "description" : item1["description"],
            "link" : item1["link"],
            
        }

        word_add = WordLinkvd(**data_obj1)
        id_victimdevice = VictimDevice(link_id = item["link_id"])#使用id連接wordlink
        word_add.victimdevice = id_victimdevice
        session.add(word_add)
    session.commit()
    session.close()
    
for item in hackinfo:
    data_obj = {
        "link_id": item["link_id"],
        "ip": item["ip"],
        "vul_type": item["vul_type"],
        "cvss": item["cvss"],
        "cve": item["cve"],
    }

    session = create_session()

    session.add(HackInfo(**data_obj))
    
    for item1 in item["scan_result"]:
        data_obj1 = {
            "description" : item1["description"],
            "link" : item1["link"],
            
        }

        word_add = WordLinkhi(**data_obj1)
        id_hackinfo = HackInfo(link_id = item["link_id"])#使用id連接wordlink
        word_add.hackinfo = id_hackinfo
        session.add(word_add)
    
    
    session.commit()
    session.close()
  
    
for item in dataexport:
    data_obj = {
        #"id": item["id"],
        "probe_time": item["probe_time"],
        "c2_ip": item["c2_ip"],
        "country": item["country"],
        "c2_type": item["c2_type"],
        "domain_name": item["domain_name"],
    }

    session = create_session()

    session.add(DataExport(**data_obj))
    session.commit()
    session.close()

for item in product:
    data_obj = {
        #"id": item["id"],
        "product_id": item["product_id"],
        "product_name": item["product_name"],
        "version": item["version"],
        "vendor": item["vendor"],
        "add_datetime": item["add_datetime"],
    }

    session = create_session()

    session.add(Product(**data_obj))
    
    for item1 in item["image"]:
        data_obj1 = {
            "img_src" : item1["img_src"],
            "link" : item1["link"],
            
        }
        image_add = ImageLinkpro(**data_obj1)
        id_product = Product(product_id = item["product_id"])#使用product_id連接imagelink
        image_add.product = id_product
        session.add(image_add)
    session.commit()
    session.close()
    
    
for item in exploit:
    data_obj = {

        "date": item["date"],
        "v": item["v"],
        "title": item["title"],
        "type": item["type"],
        "platform": item["platform"],
        "author": item["author"],
    }

    session = create_session()

    session.add(Exploit(**data_obj))
    session.commit()
    session.close()
    
for item in portactivity:
    data_obj = {
        "create_time": item["create_time"],
        "ip": item["ip"],
        "dns_set": item["dns_set"],
        "port_type": item["port_type"],
        "ports": item["ports"],
        "add_ports": item["add_ports"],
        "delete_ports": item["delete_ports"],
    }

    session = create_session()

    session.add(PortActivity(**data_obj))
        
    session.commit()
    session.close()

for item in apt:
    data_obj = {
        "first_seen": item["first_seen"],
        "last_seen": item["last_seen"],
        "domain_name": item["domain_name"],
        "ip": item["ip"],
        "ports": item["ports"],
        "country": item["country"],
        "group": item["group"],
        "activity_type": item["activity_type"],
    }

    session = create_session()

    session.add(Apt(**data_obj))
        
    session.commit()
    session.close()
    
#test    
"""   
result = session.query(PortActivity).all()
for row in result:
    print(row.id, end=" ")
    print(row.ip)
    
result = session.query(Apt).all()
for row in result:
    print(row.id, end=" ")
    print(row.ip)
"""