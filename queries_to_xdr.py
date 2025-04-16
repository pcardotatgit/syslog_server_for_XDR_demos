'''
    create incidents and sightings
    version 20250202
'''
import requests
import json
import sys
import time
from datetime import datetime, date, timedelta
import hashlib
from crayons import *
import random
import string

# Get the current date/time
dateTime = datetime.now()


def HOW_TO_DO_TO_CREATE_XDR_INCIDENT():
    var='''
    get and create indicators => JSON = Indicator_json
    get and create sightings => JSON = read_sightings
    create incident container => JSON  = incident_json,incident_xid
    create a sighting list : sightings=[]
    create a relationship list : relationships=[]
    for each sighting
        create sighting xid, sighting_transient_id and json sighting => append JSON to sightings[]
        if sighting belongs to an Incident:
            create a relationship between sighting and the Incident
            create a relationship_xid then create the relationship 
            append this new relationship to the relationship list
            create a relationships between the sightings and it's transiant id and the indicator_id
        else:
            don't create any relationship to incident
            if sighting has indicator:
                create a relationships between the sightings and it's transiant id and the indicator_id
            
    create the bundle JSON with : incident_json, sightings, relationships
    POST the bundle'''
    return 1    
 
def get_indicator_id_for_ips_sightings(indicator_info):
    indicator_id=indicator_info.split('***')[0]
    return(indicator_id)
    
def date_plus_x_days(nb):
    print()
    print(green(' ----> def date_plus_x_days() in queries_to_xdr.py : >',bold=True))
    print()
    current_time = datetime.utcnow()
    start_time = current_time + timedelta(days=nb)
    timestampStr = start_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return(timestampStr)
    
def post_bundle(json_payload,access_token,host):
    print()
    print(green(' ----> def post_bundle() in queries_to_xdr.py : >',bold=True))
    print()
    url=f"{host}/ctia/bundle/import"
    headers = {'Authorization':'Bearer {}'.format(access_token), 'Content-Type':'application/json', 'Accept':'application/json'}
    response = requests.post(url, headers=headers,data=json_payload)
    rep = json.dumps(response.json(),indent=4,sort_keys=True, separators=(',', ': '))
    print(rep)
    if response.status_code==200 or response.status_code==201:
        return 1
    else:
        return 0
  
def create_bundle_json(source,incidents,sightings,indicators,judgments_new, relationships_new):
    print()
    print(green(' ----> def create_new_incident_into_xdr() in queries_to_xdr.py : >',bold=True))
    print()
    bundle_object={}
    bundle_object["source"] = source
    if incidents!=[]:
        bundle_object["incidents"] = incidents
    if sightings!=[]:
        bundle_object["sightings"] = sightings
    if indicators!=[]:
        bundle_object["indicators"] = indicators
    if judgments_new!=[]:
        bundle_object["judgements"] = judgments_new
    if relationships_new!=[]:
        bundle_object["relationships"] = relationships_new
    return(bundle_object)
 
def create_relationship_object(source_xid, target_xid, relationship_xid, relationship_type,source):
    print()
    print(green(' ----> create_relationship_object() in queries_to_xdr.py: >',bold=True))
    print()
    relationship_json = {}
    relationship_json["external_ids"] = ["transient:"+relationship_xid]
    relationship_json["source_ref"] = source_xid
    relationship_json["target_ref"] = target_xid
    relationship_json["source"] = source
    relationship_json["relationship_type"] = relationship_type
    relationship_json["type"] = "relationship"
    relationship_json["id"] = "transient:"+relationship_xid
    print(' relationships :\n',cyan(relationship_json,bold=True))
    return json.dumps(relationship_json)
    
def generate_relationship_xid(source_xid, target_xid):
    print()
    print(green(' ----> def generate_relationship_xid() in queries_to_xdr.py  : >',bold=True))
    print()
    hash_value = hashlib.sha1((source_xid + target_xid).encode('utf-8'))
    hash_value = hash_value.hexdigest()
    relationship_xid = "sxo-relationship-" + hash_value
    return relationship_xid
    
def create_sighting_xid(sighting_title):
    print()
    print(green(' ----> def create_sighting_xid() in queries_to_xdr.py : >',bold=True))
    print()
    d = datetime.now()
    current_time = d.strftime("%d/%m/%Y %H:%M:%S")
    nombre=random.randint(1, 10)
    texte=sighting_title+id_generator(nombre, "6793YUIO")
    hash_strings = [texte, current_time]
    hash_input = "|".join(hash_strings)
    hash_value = hashlib.sha256(hash_input.encode('utf-8')).hexdigest()
    sighting_xid = "sxo-sighting-" + hash_value
    print("  - Sighting External ID : ",cyan(sighting_xid,bold=True))
    return sighting_xid

def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
    # Generates a random ID
    print()
    print(green(' ----> def id_generator() in queries_to_xdr.py : >',bold=True))
    print()
    return (''.join(random.choice(chars) for _ in range(size)))
    
def create_incident_xid():
    print()
    print(green(' ----> def create_incident_xid() in queries_to_xdr.py : >',bold=True))
    print()
    hash_strings = [ "some_string to put here" + str(time.time())]
    hash_input = "|".join(hash_strings)
    hash_value = hashlib.sha256(hash_input.encode('utf-8')).hexdigest()
    incident_xid = 'transient:sxo-incident-' + hash_value
    print("  - Incident External ID : ",cyan(incident_xid,bold=True))
    return incident_xid
    
def create_sighting_json(xid,this_sighting):
    #start_date = dateTime.strftime("%Y-%m-%dT%H:%M:%SZ")
    print()
    print(green(' ----> def create_sighting_json() in queries_to_xdr.py : >',bold=True))
    print()    
    print()
    print(' sighting :\n ',red(this_sighting,bold=True))
    print()
    sighting_obj_json = {}
    sighting_obj_json["confidence"] = this_sighting["confidence"]
    print("   - Get Observables and add them into sighting definition")
    if 'observables' in this_sighting.keys():
        sighting_obj_json["observables"] = this_sighting["observables"]
    print("   - Get Targets and add them into sighting definition")
    if 'targets' in this_sighting.keys():
        sighting_obj_json["targets"] = this_sighting["targets"]
    sighting_obj_json["external_ids"] = [xid]
    sighting_obj_json["id"] ="transient:"+xid 
    if "description" in this_sighting.keys():
        sighting_obj_json["description"] = this_sighting["description"]
    if "short_description" in this_sighting.keys():    
        sighting_obj_json["short_description"] = this_sighting["short_description"] 
    if "title" in this_sighting.keys(): 
        sighting_obj_json["title"] = this_sighting["title"]
    sighting_obj_json["source"] = this_sighting["source"].replace(' (cisco-jefflen)','')
    sighting_obj_json["type"] = "sighting"
    # SIGHTING DATE HERE
    #sighting_obj_json["observed_time"] = {"start_time": dateTime.strftime("%Y-%m-%dT%H:%M:%SZ") }
    sighting_obj_json["observed_time"] = this_sighting["observed_time"]
    if "tlp" in this_sighting.keys():
        sighting_obj_json["tlp"] = this_sighting["tlp"]
    sighting_obj_json["severity"] = this_sighting["severity"]
    if 'sensor' in this_sighting.keys():
        sighting_obj_json['sensor'] = this_sighting['sensor']
    if 'resolution' in this_sighting.keys():
        sighting_obj_json['resolution'] = this_sighting['resolution']
    print("   - Get sighting observable relations and add them into sighting definition")
    relation_list=[]
    if 'relations' in this_sighting.keys():
        sighting_obj_json["relations"]=this_sighting['relations']
    print()
    print(' Sighting JSON :\n',cyan(sighting_obj_json,bold=True))
    return (sighting_obj_json['id'],json.dumps(sighting_obj_json))
    
def post_bundle(host_for_token,access_token,bundle):
    print()
    print(green(' ----> def post_bundle() in queries_to_xdr.py: >',bold=True))
    print()
    print(yellow("  - Let's connect to XDR API to create the Incident into XDR",bold=True))
    print()
    url = f"{host_for_token}/iroh/private-intel/bundle/import?external-key-prefixes=sxo"
    print('url : ',url)
    headers = {'Authorization':'Bearer {}'.format(access_token), 'Content-Type':'application/json', 'Accept':'application/json'}
    response = requests.post(url, data=bundle,headers=headers)
    print()  
    print(response.status_code)
    print(response.json())    
    if response.status_code==401:
        access_token=get_ctr_token(host_for_token,client_id,client_password)
        headers = {'Authorization':'Bearer {}'.format(access_token), 'Content-Type':'application/json', 'Accept':'application/json'}        
        response = requests.post(url, data=bundle,headers=headers)           
    if response.status_code==200:
        print(green(response.status_code,bold=True))
        print()         
        print(green("Ok Done Incident created",bold=True))         
        print()    
        #print(response.json())    
        print(cyan(json.dumps(response.json(),sort_keys=True,indent=4, separators=(',', ': ')),bold=True))
        print() 
        return 1
    else:
        return 0

def generate_incident_json(file):
    print()
    print(green(' ----> generate_incident_json() in queries_to_xdr.py: >',bold=True))
    print()
    print(yellow("- > Step 1.0 Read Incident Details",bold=True))
    print('incident file : ',yellow(file,bold=True))
    with open(file,'r') as file:
        text_data=file.read()
        incident_details=json.loads(text_data)[0]    
    print()
    print('incident_details : ',yellow(incident_details,bold=True))
    print('type incident_details : ',yellow(type(incident_details),bold=True))
    print()
    print(yellow("- > Step 1.1 create_incident_xid",bold=True))
    # Build the incident objects
    #xid="transient:"+create_incident_xid() DEBUG PATRIKC
    xid=create_incident_xid()
    print(yellow("- > Step 1.2 generate_incident_json",bold=True))
    incident_object = {}
    incident_object["description"] = incident_details['description']
    incident_object["schema_version"] = "1.3.9"
    incident_object["type"] = "incident"
    incident_object["source"] = "FTD Syslog Server"
    incident_object["short_description"] = incident_details['short_description']
    incident_object["title"] = incident_details['title']
    incident_object["incident_time"] = { "discovered": dateTime.strftime("%Y-%m-%dT%H:%M:%SZ"), "opened": dateTime.strftime("%Y-%m-%dT%H:%M:%SZ") }
    incident_object["status"] = "New"
    incident_object["tlp"] = incident_details['tlp']
    incident_object["confidence"] = incident_details['confidence']
    incident_object["severity"] = incident_details['severity']
    incident_object["id"] = xid
    if 'techniques' in incident_details.keys():
        incident_object["techniques"] = incident_details['techniques']
    if 'tactics' in incident_details.keys():
        incident_object["tactics"] = incident_details['tactics']
    incident_object["categories"]:[categories[3]]
    incident_object["discovery_method"]:discover_method[2]
    if 'promotion_method' in incident_details.keys():
        incident_object["promotion_method"]=incident_summary[0]['promotion_method']   
    else:
        incident_object["promotion_method"]="Automated"
    if 'scores_asset' in incident_details.keys() and 'scores_ttp' in incident_details.keys():
        incident_object["scores"]={}
        incident_object["scores"]["asset"]=incident_details["scores_asset"]     
        incident_object["scores"]["ttp"]=incident_details["scores_ttp"]
        incident_object["scores"]["global"]=incident_object["scores"]["asset"]*incident_object["scores"]["ttp"]  
    incident_json = json.dumps(incident_object)
    payload = json.dumps(incident_object,indent=4,sort_keys=True, separators=(',', ': '))
    #print(response.json())     
    print()
    print(' Incidents JSON :\n',cyan(payload,bold=True))
    return(incident_json,xid)
    
# here under create judgment functions
def create_judgment_external_id(judgment_input):
    print()
    print(green(' ----> create_judgment_external_id() in queries_to_xdr.py: >',bold=True))
    print()
    # hash judgment without transient ID
    hash_input = json.dumps(judgment_input)
    hash_value = hashlib.sha256(hash_input.encode('utf-8')).hexdigest()
    judgment_external_id = "xdr-automation-judgment-" + hash_value
    return judgment_external_id
    
def generate_judgment_json(object):
    print()
    print(green(' ----> generate_judgment_json() in queries_to_xdr.py : >',bold=True))
    print()
    judgment_object = {}
    judgment_object["schema_version"] = "1.0.19"
    judgment_object["observable"] = { "value":object,"type":"ip" }
    judgment_object["type"] = "judgement"
    judgment_object["disposition"] = 2
    judgment_object["reason"] = "Watch List"
    judgment_object["disposition_name"] = "Malicious"
    judgment_object["priority"] = 95
    judgment_object["severity"] = "High"
    judgment_object["timestamp"] = dateTime.strftime("%Y-%m-%dT%H:%M:%SZ")
    judgment_object["valid_time"] = { "start_time": dateTime.strftime("%Y-%m-%dT00:00.000Z"), "end_time": date_plus_x_days(14) }
    judgment_object["confidence"] = "High"
    judgment_external_id = create_judgment_external_id(judgment_object)
    judgment_object["external_ids"] = [judgment_external_id] 
    judgment_object["id"] = "transient:" + judgment_external_id  
    # here under to customize manually
    judgment_object["tlp"] = "amber"
    judgment_object["source"] = "Custom_Syslog_Server"
    return judgment_object
    
def get2(host,access_token,url,offset,limit):    
    '''
        API Call with offset and limit
    '''
    print()
    print(green('def get2() : in queries_to_xdr.py >',bold=True))
    print()
    headers = {'Authorization':'Bearer {}'.format(access_token), 'Content-Type':'application/json', 'Accept':'application/json'}
    url = f"{host}{url}?limit={limit}&offset={offset}"
    print(yellow(url))
    print()   
    print(magenta('--> API CALL :',bold=True))
    response = requests.get(url, headers=headers)
    return response
    
def get_feeds(host,access_token):
    print()
    print(green('def get_feeds() : in queries_to_xdr.py >',bold=True))
    print()
    #fb = open("./feeds/z_json_feeds_list.json", "w")
    #fd = open("./judgments/z_judgements_id_list.txt", "w")
    #fc = open("./judgments/z_judgment_list.txt", "w")
    url = f"/ctia/feed/search"
    item_list=[]
    offset=0
    limit=1000 
    index=0
    print()   
    print(magenta('--> CALL  A SUB FUNCTION :',bold=True))
    response = get2(host,access_token,url,offset,limit)
    payload = json.dumps(response.json(),indent=4,sort_keys=True, separators=(',', ': '))
    #print(response.json())    
    items=response.json()
    #fb.write(payload)
    #fb.close()
    #fc.close()
    #fd.close()
    #print()
    #print(' payload :\n ',cyan(payload,bold=True))
    #print()
    return(response.json())
    
def get_indicators(host,access_token):
    print()
    print(green('def get_indicators() : in queries_to_xdr.py >',bold=True))
    print()
    #fb = open("./indicators/z_json_indicators_list.json", "w")
    #fd = open("./indicators/z_indicators_id_list.txt", "w")
    #json_output='[\n'
    #fc = open("./indicators/z_indicators_list.txt", "w")
    url = "/ctia/indicator/search"
    offset=0
    limit=1000
    item_list=[]
    go=1 # used to stop the loop   
    while go:      
        index=0
        print()   
        print(magenta('--> CALL  A SUB FUNCTION :',bold=True))
        response = get2(host,access_token,url,offset,limit)
        payload = json.dumps(response.json(),indent=4,sort_keys=True, separators=(',', ': '))
        #print(payload)    
        items=response.json()
        for item in items: 
            index+=1
            #print(yellow(item,bold=True))
            temp_dict={}
            temp_dict[item['title']]=item['id']
            item_list.append(temp_dict)
            #fb.write(json.dumps(item))
            #fb.write(',\n')
            #json_output+=json.dumps(item)
            #json_output+=',\n'
            #fc.write('\n')   
            #fd.write(item['title']+';'+item['id'])
            #fd.write('\n')             
        if index>=limit-1:
            go=1
            offset+=index-1
        else:
            go=0
    #json_output=json_output[:-2]
    #json_output+=']'
    #fb.write(json_output)
    #fb.close()
    #fc.close()
    #fd.close()
    return(item_list)
    
def create_feed(host,access_token,indicator_id,feed_name):
    print()
    print(green('def create_feed() in queries_to_xdr.py : >',bold=True))
    print()
    # Get the current date/time
    dateTime = datetime.now()
    # Build the feed object
    feed_object = {}
    feed_object["schema_version"] = "1.0.19"
    feed_object["indicator_id"] = indicator_id
    feed_object["type"] = "feed"
    feed_object["output"] = "observables"
    feed_object["title"] = feed_name
    feed_object["tlp"] = "amber"
    feed_object["lifetime"] = {
      "start_time": dateTime.strftime("%Y-%m-%dT00:00.000Z")
    }
    feed_object["timestamp"] = dateTime.strftime("%Y-%m-%dT00:00.000Z")
    feed_object["feed_type"] = "indicator"
    payload = json.dumps(feed_object)
    #print()
    #print(' feed JSON : \n',cyan(payload,bold=True))
    #POST / Create Indicator into XDR
    url = f'{host}/ctia/feed'
    headers = {'Authorization':'Bearer {}'.format(access_token), 'Content-Type':'application/json', 'Accept':'application/json'}
    print()   
    print(magenta('--> API CALL:',bold=True))
    response = requests.post(url, headers=headers, data=payload)
    #print()
    #print (yellow(response,bold=True))  
    #print()
    #print(green(response.json(),bold=True))  
    feed_id=response.json()['id']
    #print(' feed id : ',green(response.json(),bold=True))     
    return(feed_id)
    
def create_indicator(host,access_token,indicator_name,indicator_type,description):
    print()
    print(green('def create_indicator() in queries_to_xdr.py : >',bold=True))
    print()
    if indicator_type=="IPv4":
        indic_type=["IP Watchlist"]
    elif indicator_type=="IPv6":
        indic_type=["IP Watchlist"]  
    elif indicator_type=="DOMAIN":
        indic_type=["Domain Watchlist"] 
    elif indicator_type=="URL":
        indic_type=["URL Watchlist"]  
    elif indicator_type=="SHA256":
        indic_type= ["File Hash Watchlist"]
    else:
        indicator_type=["IP Watchlist"]
    # Get the current date/time
    dateTime = datetime.now()
    # Build the indicator objects
    indicator_object = {}
    indicator_object["description"] = description
    indicator_object["producer"] = "FTD Syslog Server"
    indicator_object["schema_version"] = "1.0.19"
    indicator_object["type"] = "indicator"
    indicator_object["source"] = "xdr-sidecar"
    indicator_object["short_description"] = description
    indicator_object["title"] = indicator_name
    indicator_object["indicator_type"] = indic_type
    indicator_object["severity"] = "Info"
    indicator_object["tlp"] = "amber"
    indicator_object["timestamp"] = dateTime.strftime("%Y-%m-%dT00:00.000Z")
    indicator_object["confidence"] = "High"
    # convert dict to json
    payload = json.dumps(indicator_object)   
    #print()
    #print(' indicator JSON : \n',cyan(payload,bold=True))
    #POST / Create Indicator into XDR
    url = f'{host}/ctia/indicator'
    headers = {'Authorization':'Bearer {}'.format(access_token), 'Content-Type':'application/json', 'Accept':'application/json'}
    #print()   
    print(magenta('--> API CALL :',bold=True))
    response = requests.post(url, headers=headers, data=payload)
    #print()
    #print (yellow(response,bold=True))  
    #print()
    #print(green(response.json(),bold=True))  
    indicator_id=response.json()['id']
    return(indicator_id)
