from typing import Union
from typing import List
from fastapi import Body, FastAPI ,HTTPException
from pydantic import BaseModel

import requests
import json
from pprint import pprint

from main_all import GeoIP
from main_all import Checkpoint, WordLinkcp
from main_all import DomainName, WordLinkdn
from main_all import Ioc, WordLinkio
from main_all import create_session 
from main_all import Threat, WordLinkth
from main_all import VictimDevice, WordLinkvd
from main_all import HackInfo, WordLinkhi
from main_all import DataExport
from main_all import Product, ImageLinkpro
from main_all import Exploit
from main_all import PortActivity
from main_all import Apt

#from fastapi.responses import HTMLResponse


#uvicorn api_all:app --reload


app = FastAPI()
session = create_session()
class WordLinkFA(BaseModel):
    description : str = None
    link : str = None
    
    
### GeoIP
class GeoIPFA(BaseModel):
    id: int = 0 
    ip : str = None
    lat : float = 0.0
    lng : float = 0.0
    size :int = 0  
    
@app.get("/worldmap",response_model = List[GeoIPFA])
def read_item ():
    L = []
    A = {}
    
    result = session.query(GeoIP).all()
    for row in result:
        A["id"] = row.id
        A["ip"] = row.ip
        A["lat"] = row.lat
        A["lng"] = row.lng
        A["size"] = row.size
            
            
        L.append(A)
        A = {}
    return L
    
    
### Checkpoint 有問題
class CheckpointFA(BaseModel):
    id : int = 0
    first_date: str = None
    last_modified : str = None
    ioc : str = None
    ip : str = None
    port : str = None
    jarm : str = None
    jarm_type : str = None
    scan_result : WordLinkFA = None 
    
@app.get("/checkpoint",response_model = List[CheckpointFA])
def read_item (time : str = None, dn : str = None , ip : str = None):
    L = []
    A = {}
    L1 = []
    A1 = {}
    
    result = session.query(Checkpoint).all()
    for row in result:
        if row.wordlinkcp == []:
            A["id"] = row.id
            A["first_date"] = row.first_date
            A["last_modified"] = row.last_modified
            A["ioc"] = row.ioc
            A["ip"] = row.ip
            A["port"] = row.port
            A["jarm"] = row.jarm
            A["jarm_type"] = row.jarm_type
            result2 = session.query(Checkpoint).filter(Checkpoint.link_id == row.link_id).all()
            for row1 in result2:
                    if row1.wordlinkcp!=[]:
                        A1["description"] = row1.wordlinkcp[0].description
                        A1["link"] = row1.wordlinkcp[0].link
                        L1.append(A1)
                        A1={}
            A["scan_result"] = L1
            
            L.append(A)
            A = {}  
                 
    return L


@app.post("/checkpoint")
def create_item(checkpoint: CheckpointFA):
    return checkpoint.dict()


@app.get("/checkpoint/export")
def create_url(format:str = "json"):
    return "http://..."

@app.get("/checkpoint/{Checkpoint_id}",response_model = List[CheckpointFA])
def read_item1(Checkpoint_id: int):
    
    L = []
    A = {}
    L1 = []
    A1 = {}
    result = session.query(Checkpoint).filter(Checkpoint.link_id == Checkpoint_id).all()
    if result != []: #找得到東西
        for row in result:
            if row.wordlinkcp == []:
                A["id"] = row.id
                A["first_date"] = row.first_date
                A["last_modified"] = row.last_modified
                A["ioc"] = row.ioc
                A["ip"] = row.ip
                A["port"] = row.port
                A["jarm"] = row.jarm
                A["jarm_type"] = row.jarm_type
                
                result2 = session.query(Checkpoint).filter(Checkpoint.link_id == row.link_id).all()
                for row1 in result2:
                        if row1.wordlinkcp!=[]:
                            A1["description"] = row1.wordlinkcp[0].description
                            A1["link"] = row1.wordlinkcp[0].link
                            L1.append(A1)
                            #print(A1)
                            A1={}
                A["scan_result"] = L1
                
                L.append(A)
                A = {}
             
    
        return L
    else:
        raise HTTPException(status_code=404, detail="id not found")
    
    
### DomainName 有問題

class DomainNameFA(BaseModel):
    id: int = 0 
    first_seen: str = None
    last_seen : str = None
    dn : WordLinkFA = None
    ip : WordLinkFA = None
    port :  str  = None
    country : str = None
    group : str = None
    register_email : WordLinkFA = None
    valid_date : str = None
    report : WordLinkFA = None  
    
@app.get("/domain",response_model = List[DomainNameFA])
def read_item (time : str = None, dn : str = None , ip : str = None):
    L = []
    A = {}
    L1 = []
    A1 = {}
    
    result = session.query(DomainName).all()
    for row in result:
        if row.wordlinkdn == []:
            A["id"] = row.id
            A["first_seen"] = row.first_seen
            A["last_seen"] = row.last_seen
            A["port"] = row.port
            A["country"] = row.country
            A["group"] = row.group
            A["valid_date"] = row.valid_date
            
            result2 = session.query(DomainName).filter(DomainName.link_id == row.link_id).all()
            for row1 in result2:
                    if row1.wordlinkdn!=[] and row1.wordlinkdn[0].wordlinktype == "dn":
                        A1["description"] = row1.wordlinkdn[0].description
                        A1["link"] = row1.wordlinkdn[0].link
                        L1.append(A1)
                        #print(A1)
                        A1={}
            A["dn"] = L1
            L1=[]#重新放別的東西
            
            for row2 in result2:
                    if row2.wordlinkdn!=[] and row2.wordlinkdn[0].wordlinktype == "ip":
                        A1["description"] = row2.wordlinkdn[0].description
                        A1["link"] = row2.wordlinkdn[0].link
                        L1.append(A1)
                        #print(A1)
                        A1={}
            A["ip"] = L1
            L1=[]
            
            for row3 in result2:
                    if row3.wordlinkdn!=[] and row3.wordlinkdn[0].wordlinktype == "register_email":
                        A1["description"] = row3.wordlinkdn[0].description
                        A1["link"] = row3.wordlinkdn[0].link
                        L1.append(A1)
                        #print(A1)
                        A1={}
            A["register_email"] = L1
            L1=[]
            
            for row4 in result2:
                    if row4.wordlinkdn!=[] and row4.wordlinkdn[0].wordlinktype == "report":
                        A1["description"] = row4.wordlinkdn[0].description
                        A1["link"] = row4.wordlinkdn[0].link
                        L1.append(A1)
                        #print(A1)
                        A1={}
            A["report"] = L1
            L1=[]
            
            L.append(A)
            A = {}
   
    return L


@app.get("/domain/export")
def create_url(Format:str = "json"):
    return "http://..."

@app.get("/domain/{DomainName_id}/whois",response_model = List[DomainNameFA])
def check_item(DomainName_id:int):
        L = []
        A = {}
        L1 = []
        A1 = {}
        result = session.query(DomainName).filter(DomainName.link_id == DomainName_id).all()
        if result != []: #找得到東西
            for row in result:
                if row.wordlinkdn == []:
                    A["id"] = row.id
                    A["first_seen"] = row.first_seen
                    A["last_seen"] = row.last_seen
                    A["port"] = row.port
                    A["country"] = row.country
                    A["group"] = row.group
                    A["valid_date"] = row.valid_date
                    
                    result2 = session.query(DomainName).filter(DomainName.link_id == row.link_id).all()

                    for row1 in result2:
                        if row1.wordlinkdn!=[] and row1.wordlinkdn[0].wordlinktype == "dn":
                            A1["description"] = row1.wordlinkdn[0].description
                            A1["link"] = row1.wordlinkdn[0].link
                            L1.append(A1)
                            #print(A1)
                            A1={}
                    A["dn"] = L1
                    L1=[]#重新放別的東西
                    
                    for row2 in result2:
                        if row2.wordlinkdn!=[] and row2.wordlinkdn[0].wordlinktype == "ip":
                            A1["description"] = row2.wordlinkdn[0].description
                            A1["link"] = row2.wordlinkdn[0].link
                            L1.append(A1)
                            #print(A1)
                            A1={}
                    A["ip"] = L1
                    L1=[]
                    
                    for row3 in result2:
                        if row3.wordlinkdn!=[] and row3.wordlinkdn[0].wordlinktype == "register_email":
                            A1["description"] = row3.wordlinkdn[0].description
                            A1["link"] = row3.wordlinkdn[0].link
                            L1.append(A1)
                            #print(A1)
                            A1={}
                    A["register_email"] = L1
                    L1=[]
                    
                    for row4 in result2:
                        if row4.wordlinkdn!=[] and row4.wordlinkdn[0].wordlinktype == "report":
                            A1["description"] = row4.wordlinkdn[0].description
                            A1["link"] = row4.wordlinkdn[0].link
                            L1.append(A1)
                            #print(A1)
                            A1={}
                    A["report"] = L1
                    L1=[]
                                
                    L.append(A)
                    A = {}
                 
        
            return L
        else:
            raise HTTPException(status_code=404, detail="id not found")
    
    
### Ioc 有問題
class IocFA(BaseModel):
    id : int = 0
    date : str = None
    last_modified : str = None
    dn : str = None
    ioc_source : WordLinkFA = None
    factor_1 : float = 0.0
    factor_2 : float = 0.0
    factor_3 : float = 0.0
    factor_4 : float = 0.0
    factor_5 : float = 0.0
    sum : float = 0.0

@app.get("/ioc",response_model = List[IocFA])
def read_item (time : str = None, dn : str = None , ip : str = None):
    L = []
    A = {}
    L1 = []
    A1 = {}
    
    result = session.query(Ioc).all()
    for row in result:
        if row.wordlinkio == []:
            A["id"] = row.id
            A["date"] = row.date
            A["last_modified"] = row.last_modified
            A["dn"] = row.dn
            A["factor_1"] = row.factor_1
            A["factor_2"] = row.factor_2
            A["factor_3"] = row.factor_3
            A["factor_4"] = row.factor_4
            A["factor_5"] = row.factor_5
            A["sum"] = row.sum
    
            
            result2 = session.query(Ioc).filter(Ioc.link_id == row.link_id).all()
            for row1 in result2:
                    if row1.wordlinkio!=[]:
                        A1["description"] = row1.wordlinkio[0].description
                        A1["link"] = row1.wordlinkio[0].link
                        L1.append(A1)
                        #print(A1)
                        A1={}
            A["ioc_source"] = L1
            
            L.append(A)
            A = {}
    
    return L


@app.post("/ioc")
def create_item(ioc: IocFA):
    return ioc.dict()

@app.get("/ioc/export")
def create_url(format:str = "json"):
    return "http://..."


@app.get("/ioc/{Ioc_id}",response_model = List[IocFA])
def read_item1(Ioc_id: int):
    L = []
    A = {}
    L1 = []
    A1 = {}
    result = session.query(Ioc).filter(Ioc.link_id == Ioc_id).all()
    if result != []: #找得到東西
        for row in result:
            if row.wordlinkio == []:
                A["id"] = row.id
                A["date"] = row.date
                A["last_modified"] = row.last_modified
                A["dn"] = row.dn
                A["factor_1"] = row.factor_1
                A["factor_2"] = row.factor_2
                A["factor_3"] = row.factor_3
                A["factor_4"] = row.factor_4
                A["factor_5"] = row.factor_5
                A["sum"] = row.sum
                
                result2 = session.query(Ioc).filter(Ioc.link_id == row.link_id).all()
                for row1 in result2:
                        if row1.wordlinkio!=[]:
                            A1["description"] = row1.wordlinkio[0].description
                            A1["link"] = row1.wordlinkio[0].link
                            L1.append(A1)
                            #print(A1)
                            A1={}
                A["ioc_source"] = L1
                
                L.append(A)
                A = {}
             
    
        return L
    else:
        raise HTTPException(status_code=404, detail="id not found")


       
@app.put("/ioc/{Ioc_id}")
def update_item(Ioc_id: int,ioc: IocFA= Body(..., embed=False) ):
    results = {"Ioc_id": Ioc_id, "ioc": ioc}
    return results
    #return checkpoint

@app.post("/ioc/{Ioc_id}/refresh")
def refresh(Ioc_id: int):
    return{}

    
    
### Threat 有問題

class ThreatFA(BaseModel):
    id : int = 0
    published_date: str = None
    last_modified : str = None
    cvss: str = None
    cve: str = None
    vulnerability_name: str = None
    effect_software : WordLinkFA = None
    exploit : WordLinkFA = None
    other: str = None
    possible_ip : WordLinkFA = None


@app.get("/threat",response_model = List[ThreatFA])
def read_item (time : str = None, dn : str = None , ip : str = None):
    L = []
    A = {}
    L1 = []
    A1 = {}
    
    result = session.query(Threat).all()
    for row in result:
        if row.wordlinkth == []:
            A["id"] = row.id
            A["published_date"] = row.published_date
            A["last_modified"] = row.last_modified
            A["cvss"] = row.cvss
            A["cve"] = row.cve
            A["vulnerability_name"] = row.vulnerability_name
            A["other"] = row.other
            
            result2 = session.query(Threat).filter(Threat.link_id == row.link_id).all()
            for row1 in result2:
                    if row1.wordlinkth!=[] and row1.wordlinkth[0].wordlinktype == "effect_software":
                        A1["description"] = row1.wordlinkth[0].description
                        A1["link"] = row1.wordlinkth[0].link
                        L1.append(A1)
                        #print(A1)
                        A1={}
            A["effect_software"] = L1
            L1=[]#重新放別的東西
            
            for row2 in result2:
                    if row2.wordlinkth!=[] and row2.wordlinkth[0].wordlinktype == "exploit":
                        A1["description"] = row2.wordlinkth[0].description
                        A1["link"] = row2.wordlinkth[0].link
                        L1.append(A1)
                        #print(A1)
                        A1={}
            A["exploit"] = L1
            L1=[]
            
            for row3 in result2:
                    if row3.wordlinkth!=[] and row3.wordlinkth[0].wordlinktype == "possible_ip":
                        A1["description"] = row3.wordlinkth[0].description
                        A1["link"] = row3.wordlinkth[0].link
                        L1.append(A1)
                        #print(A1)
                        A1={}
            A["possible_ip"] = L1
            L1=[]
            
            L.append(A)
            A = {}
    return L


@app.post("/threat")
def create_item(threat: ThreatFA):
    return threat.dict()

@app.get("/threat/export") #原本放最後
def create_url(format:str = "json"):
    return "http://..."

@app.get("/threat/{Threat_id}",response_model = List[ThreatFA])
def read_item1(Threat_id: int):
        L = []
        A = {}
        L1 = []
        A1 = {}
        result = session.query(Threat).filter(Threat.link_id == Threat_id).all()
        if result != []: #找得到東西
            for row in result:
                if row.wordlinkth == []:
                    A["id"] = row.id
                    A["published_date"] = row.published_date
                    A["last_modified"] = row.last_modified
                    A["cvss"] = row.cvss
                    A["cve"] = row.cve
                    A["vulnerability_name"] = row.vulnerability_name
                    A["other"] = row.other
                    
                    result2 = session.query(Threat).filter(Threat.link_id == row.link_id).all()

                    for row1 in result2:
                        if row1.wordlinkth!=[] and row1.wordlinkth[0].wordlinktype == "effect_software":
                            A1["description"] = row1.wordlinkth[0].description
                            A1["link"] = row1.wordlinkth[0].link
                            L1.append(A1)
                            #print(A1)
                            A1={}
                    A["effect_software"] = L1
                    L1=[]#重新放別的東西
                    
                    for row2 in result2:
                        if row2.wordlinkth!=[] and row2.wordlinkth[0].wordlinktype == "exploit":
                            A1["description"] = row2.wordlinkth[0].description
                            A1["link"] = row2.wordlinkth[0].link
                            L1.append(A1)
                            #print(A1)
                            A1={}
                    A["exploit"] = L1
                    L1=[]
                    
                    for row3 in result2:
                        if row3.wordlinkth!=[] and row3.wordlinkth[0].wordlinktype == "possible_ip":
                            A1["description"] = row3.wordlinkth[0].description
                            A1["link"] = row3.wordlinkth[0].link
                            L1.append(A1)
                            #print(A1)
                            A1={}
                    A["possible_ip"] = L1
                    L1=[]
                                
                    L.append(A)
                    A = {}
                 
            return L
        else:
            raise HTTPException(status_code=404, detail="id not found")

        
@app.put("/threat/{Threat_id}")
def update_item(Threat_id: int,threat: ThreatFA= Body(..., embed=False) ):
    results = {"Threat_id": Threat_id, "threat": threat}
    return results




### VictimDevice 有問題
"""
class WordLinkFA(BaseModel):
    description : str = None
    link : str = None
"""

class VictimDeviceFA(BaseModel):
    id : int = 0 
    ip: str = None
    country: str = None
    vul_type: str = None
    scan_result: WordLinkFA = None
    cvss: str = None
    cve: str = None
    add_date: str = None
    
@app.get("/victim_device",response_model = List[VictimDeviceFA])
def read_item (time : str = None, dn : str = None , ip : str = None):
    L = []
    A = {}
    L1 = []
    A1 = {}
    
    result = session.query(VictimDevice).all()
    for row in result:
        if row.wordlinkvd == []:
            A["id"] = row.id
            A["ip"] = row.ip
            A["country"] = row.country
            A["vul_type"] = row.vul_type
            A["cvss"] = row.cvss
            A["cve"] = row.cve
            A["add_date"] = row.add_date
            
            result2 = session.query(VictimDevice).filter(VictimDevice.link_id == row.link_id).all()
            for row1 in result2:
                    if row1.wordlinkvd!=[]:
                        A1["description"] = row1.wordlinkvd[0].description
                        A1["link"] = row1.wordlinkvd[0].link
                        L1.append(A1)
                        #print(A1)
                        A1={}
            A["scan_result"] = L1
            
            L.append(A)
            A = {}
    return L
    

###HackInfo 有問題
"""
class WordLinkFA(BaseModel):
    description : str = None
    link : str = None
"""

class HackInfoFA(BaseModel):
    id : int = 0 
    ip: str = None
    vul_type: str = None
    cvss: str = None
    cve: str = None
    scan_result: WordLinkFA = None

@app.get("/hack_info",response_model = List[HackInfoFA])
def read_item (time : str = None, dn : str = None , ip : str = None):
    L = []
    A = {}
    L1 = []
    A1 = {}
    
    result = session.query(HackInfo).all()
    for row in result:
        if row.wordlinkhi == []:
            A["id"] = row.id
            A["ip"] = row.ip
            A["vul_type"] = row.vul_type
            A["cvss"] = row.cvss
            A["cve"] = row.cve
            
            result2 = session.query(HackInfo).filter(HackInfo.link_id == row.link_id).all()
            for row1 in result2:
                    if row1.wordlinkhi!=[]:
                        A1["description"] = row1.wordlinkhi[0].description
                        A1["link"] = row1.wordlinkhi[0].link
                        L1.append(A1)
                        #print(A1)
                        A1={}
            A["scan_result"] = L1
            
            L.append(A)
            A = {}
    
    return L    


### DataExport
class DataExportFA(BaseModel):
    id : int = 0
    probe_time: str = None
    c2_ip: str = None
    country : str = None
    c2_type : str = None
    domain_name : str = None
    
@app.get("/data_export",response_model = List [DataExportFA])
def read_item (time : str = None, dn : str = None , ip : str = None):
    L = []
    A = {}
    result = session.query(DataExport).all()
    for row in result:
        A["id"] = row.id
        A["probe_time"] = row.probe_time
        A["c2_ip"] = row.c2_ip
        A["country"] = row.country
        A["c2_type"] = row.c2_type
        A["domain_name"] = row.domain_name
        L.append(A)
        A = {}

    return L


@app.get("/data_export/export")
def create_url(Format:str = "json"):
    L = []
    A = {}
    result = session.query(DataExport).all()
    for row in result:
        A["id"] = row.id
        A["probe_time"] = row.probe_time
        A["c2_ip"] = row.c2_ip
        A["country"] = row.country
        A["c2_type"] = row.c2_type
        A["domain_name"] = row.domain_name
        L.append(A)
        A = {}

    return "http://..."

### Product
class ImageLinkFA(BaseModel):
    img_src: str = None
    link : str = None


class ProductFA(BaseModel):
    id : int = 0
    product_id : str = None
    product_name : str = None
    version : str = None
    vendor : str = None
    add_datetime : str = None
    image : List [ImageLinkFA] = None


@app.get("/product",response_model = List[ProductFA])
def read_item (time : str = None, dn : str = None , ip : str = None):
    L = []
    A = {}
    L1 = []
    A1 = {}

    result = session.query(Product).all()
    for row in result:
        if row.imagelinkpro == []:
            A["id"] = row.id
            A["product_id"] = row.product_id
            A["product_name"] = row.product_name
            A["version"] = row.version
            A["vendor"] = row.vendor
            A["add_datetime"] = row.add_datetime
            result2 = session.query(Product).filter(Product.product_id == row.product_id).all()
            for row1 in result2:
                    if row1.imagelinkpro!=[]:
                        A1["img_src"] = row1.imagelinkpro[0].img_src
                        A1["link"] = row1.imagelinkpro[0].link
                        L1.append(A1)
                        #print(A1)
                        A1={}
            A["image"] = L1
                        
            L.append(A)
            A = {}
             
    
    return L



@app.get("/product/{Product_id}/pics",response_model = List[ProductFA])
def read_item1(Product_id: int):
    
    
    L = []
    A = {}
    L1 = []
    A1 = {}
    result = session.query(Product).filter(Product.product_id == Product_id).all()
    if result != []: #找得到東西
        for row in result:
            if row.imagelinkpro == []:
                A["id"] = row.id
                A["product_id"] = row.product_id
                A["product_name"] = row.product_name
                A["version"] = row.version
                A["vendor"] = row.vendor
                A["add_datetime"] = row.add_datetime
                result2 = session.query(Product).filter(Product.product_id == row.product_id).all()
                for row1 in result2:
                        if row1.imagelinkpro!=[]:
                            A1["img_src"] = row1.imagelinkpro[0].img_src
                            A1["link"] = row1.imagelinkpro[0].link
                            L1.append(A1)
                            #print(A1)
                            A1={}
                A["image"] = L1
                        
                L.append(A)
                A = {}
             
    
        return L
    else:
        raise HTTPException(status_code=404, detail="id not found")


### Exploit
class ExploitFA(BaseModel):
    id : int = 0
    date : str = None
    v : str = None
    title : str = None
    type: str = None
    platform : str = None
    author : str = None

@app.get("/exploit",response_model = List [ExploitFA])
def read_item (time : str = None, dn : str = None , ip : str = None):
    
    L = []
    A = {}
    result = session.query(Exploit).all()
    for row in result:
        A["id"] = row.id
        A["date"] = row.date
        A["v"] = row.v
        A["title"] = row.title
        A["type"] = row.type
        A["platform"] = row.platform
        A["author"] = row.author
        L.append(A)
        A = {}

    return L



@app.get("/exploit/{Exploit_id}/download")
def create_url(Format:str = "json"):
    
    L = []
    A = {}
    result = session.query(Exploit).all()
    for row in result:
        A["id"] = row.id
        A["date"] = row.date
        A["v"] = row.v
        A["title"] = row.title
        A["type"] = row.type
        A["platform"] = row.platform
        A["author"] = row.author
        L.append(A)
        A = {}

    
    return "http://..."


### PortActivity
class PortActivityFA(BaseModel):
    id : int = 0
    create_time: str
    ip: str
    dns_set : str
    port_type : str
    ports :  str 
    add_ports :  str 
    delete_ports :  str 


@app.get("/port_activity",response_model = List [PortActivityFA])
def read_item ():
    L = []
    A = {}
    result = session.query(PortActivity).all()
    for row in result:
        A["id"] = row.id
        A["create_time"] = row.create_time
        A["ip"] = row.ip
        A["dns_set"] = row.dns_set
        A["port_type"] = row.port_type
        A["ports"] = row.ports
        A["add_ports"] = row.add_ports
        A["delete_ports"] = row.delete_ports
    
        L.append(A)
        A = {}
    return L

@app.get("/port_activity/export")
def create_url(Format:str = "json"):
    return "http://..."







###Apt
class AptFA(BaseModel):
    id : int = 0
    first_seen: str = None
    last_seen : str = None
    domain_name : str = None
    ip : str = None
    ports : str = None
    country : str = None
    group : str = None
    activity_type : str = None
    
    
@app.get("/apt",response_model = List[AptFA])
def read_item (time : str = None, dn : str = None , ip : str = None):
    L = []
    A = {}
    result = session.query(Apt).all()
    for row in result:
        A["id"] = row.id
        A["first_seen"] = row.first_seen
        A["last_seen"] = row.last_seen
        A["domain_name"] = row.domain_name
        A["ip"] = row.ip
        A["ports"] = row.ports
        A["country"] = row.country
        A["group"] = row.group
        A["activity_type"] = row.activity_type
    
        L.append(A)
        A = {}

    return L



@app.get("/apt/export") #原本放最後
def create_url(format:str = "json"):
    return "http://..."

@app.get("/apt/{Apt_id}/source",response_model = List[AptFA])
def read_item1(Apt_id: int):
    L = []
    A = {}
    result = session.query(Apt).filter(Apt.id == Apt_id).all()
    if result != []: #找得到東西
        for row in result:
            A["id"] = row.id
            A["first_seen"] = row.first_seen
            A["last_seen"] = row.last_seen
            A["domain_name"] = row.domain_name
            A["ip"] = row.ip
            A["ports"] = row.ports
            A["country"] = row.country
            A["group"] = row.group
            A["activity_type"] = row.activity_type
    
                
            L.append(A)
            A = {}
                 
    
        return L
    else:
        raise HTTPException(status_code=404, detail="id not found")