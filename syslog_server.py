#!/usr/bin/env python
'''
## Tiny Syslog Server in Python. version 20250205
##
## This is a tiny syslog server that is able to receive UDP based syslog
## A filter captures only IPS syslog from FTD devices
## Create XDR Incident when several IPS alerts ( > 10 ) exist for the same IP source to IP destination 
## 
## PRE REQUISIT !!! create an indicator Indicator name : Web_Attacks_IPv4  and a feed with Feed Name : Web_Attack_Feed
##
## TODO : Create within XDR a set of indicators if they don't exist and get their ID and sotre them into a local table
## TODO : Add some function that get the Indicators ID and attach sightings to THEM
## TODO : create mapping table between IPS alert and MITRE Technics and Tactics
##
'''

#
# here under import section
#

from crayons import *
import socketserver
from datetime import datetime, date, timedelta
import json
import time
import random
import hashlib
import sys
import requests
from queries_to_xdr import *

#
# here under global variable section
#
dateTime = datetime.now()
HOST, PORT = "0.0.0.0", 514

incidents={}
incidents_counts={}
indicator_list=[] 
save_sightings=0 # save every sightings as separate file into ./sightings for futur corellation
#
# Here under XDR Token Management functions
#
def parse_config(text_content):
    print()
    print(green('def parse_config() : >',bold=True))
    print()
    text_lines=text_content.split('\n')
    conf_result=['','','','','']
    for line in text_lines:
        print(green(line,bold=True))
        if 'ctr_client_id' in line:
            words=line.split('=')
            if len(words)==2:
                conf_result[0]=line.split('=')[1]
                conf_result[0]=conf_result[0].replace('"','')
                conf_result[0]=conf_result[0].replace("'","")
                conf_result[0]=conf_result[0].strip()
            else:
                conf_result[0]=""
        elif 'ctr_client_password' in line:
            words=line.split('=')
            if len(words)==2:
                conf_result[1]=line.split('=')[1]
                conf_result[1]=conf_result[1].replace('"','')
                conf_result[1]=conf_result[1].replace("'","")
                conf_result[1]=conf_result[1].strip()
            else:
                conf_result[1]=""  
        elif '.eu.amp.cisco.com' in line:
            conf_result[2]="https://visibility.eu.amp.cisco.com"
            conf_result[3]="https://private.intel.eu.amp.cisco.com"
        elif '.intel.amp.cisco.com' in line:
            conf_result[2]="https://visibility.amp.cisco.com"
            conf_result[3]="https://private.intel.amp.cisco.com"            
        elif '.apjc.amp.cisco.com' in line:
            conf_result[2]="https://visibility.apjc.amp.cisco.com"  
            conf_result[3]="https://private.intel.apjc.amp.cisco.com"
        elif 'profil_name' in line:
            words=line.split('=')
            if len(words)==2:
                conf_result[4]=line.split('=')[1]
                conf_result[4]=conf_result[4].replace('"','')
                conf_result[4]=conf_result[4].replace("'","")
                conf_result[4]=conf_result[4].strip()
            else:
                conf_result[4]="" 
    print(yellow(conf_result))
    return conf_result

def get_ctr_token(host_for_token,ctr_client_id,ctr_client_password):
    print()
    print(green('def get_ctr_token() : >',bold=True))
    print()
    print(yellow('Asking for new CTR token',bold=True))
    url = f'{host_for_token}/iroh/oauth2/token'
    print()
    print(url)
    print()    
    headers = {'Content-Type':'application/x-www-form-urlencoded', 'Accept':'application/json'}
    payload = {'grant_type':'client_credentials'}
    print()
    print('ctr_client_id : ',green(ctr_client_id,bold=True))
    print('ctr_client_password : ',green(ctr_client_password,bold=True))
    print()   
    print(magenta('--> API CALL :',bold=True))
    response = requests.post(url, headers=headers, auth=(ctr_client_id, ctr_client_password), data=payload)
    print(response.json())
    if 'error' in response.json().keys():
            return (0)
    reponse_list=response.text.split('","')
    token=reponse_list[0].split('":"')
    print()
    print('token : ',token[1])
    print()
    fa = open("ctr_token.txt", "w")
    fa.write(token[1])
    fa.close()
    return (token[1])    
    
def check_XDR_cnx(host_for_token,client_id,client_password):
    print()
    print(green('def check_XDR_cnx() : >',bold=True))
    print()
    access_token=get_ctr_token(host_for_token,client_id,client_password)
    if access_token!=0:
        print()   
        print(magenta('--> API CALL :',bold=True))
        if get_incidents(access_token,host_for_token):
            return 1
        else:
            return 0
    else:
        return 2

#
# XDR Incidents creation functions
#
        
def create_incident_json_for_ftd_alerts(incident_title):
    print()
    print(green('def create_incident_json_for_ftd_alerts() : >',bold=True))
    print()
    print(yellow("- > Step 1 create_incident_xid",bold=True))
    xid=create_incident_xid()
    date_and_time=dateTime.strftime("%Y-%m-%dT%H:%M:%SZ")
    print(yellow("- > Step 2 generate_incident_json",bold=True))
    incident_object = {}
    incident_object["description"] = "Source IP address had been seen launching Attacks to Destination IP address"
    incident_object["schema_version"] = "1.3.9"
    incident_object["type"] = "incident"
    incident_object["source"] = "FTD Syslog server"
    incident_object["short_description"] = "Source IP address had been seen launching Attacks to Destination IP address"
    incident_object["title"] = incident_title
    incident_object["incident_time"] = { "discovered": date_and_time, "opened": date_and_time }
    incident_object["status"] = "New"
    incident_object["tlp"] = "amber"
    incident_object["confidence"] = "High"
    incident_object["severity"] = "High"
    incident_object["techniques"] = []
    incident_object["tactics"] = ["TA0002", "TA0005", "TA0006", "TA0007", "TA0008"] # arbitrary values just for demo
    incident_object["categories"]:[categories[3]]
    incident_object["discovery_method"]:discover_method[2]
    incident_object["promotion_method"]="Automated"
    incident_object["scores"]={}
    incident_object["scores"]["asset"]=10     
    incident_object["scores"]["ttp"]=90
    incident_object["scores"]["global"]=incident_object["scores"]["asset"]*incident_object["scores"]["ttp"]
    incident_object["id"] = xid    
    incident_json = json.dumps(incident_object)
    payload = json.dumps(incident_object,indent=4,sort_keys=True, separators=(',', ': '))
    #print(response.json())     
    print()
    print(' Incidents JSON :\n',cyan(payload,bold=True))
    return(incident_json,xid)
       
def create_an_xdr_incident(all_sightings,ip_source,incident_title):
    print()
    print(green('.. def create_an_xdr_incident() : >',bold=True))
    print()
    # ASKING FOR A TOKEN TO XDR TENANT
    method="config.txt"
    if method=="config.txt":
        with open('./keys/config.txt','r') as file:
            text_content=file.read()
    ctr_client_id,ctr_client_password,host_for_token,host,profil_name = parse_config(text_content)
    print()       
    print('ctr_client_id :',ctr_client_id)
    print('ctr_client_password :',ctr_client_password)
    print('host : ',host )
    print('host_for_token : ',host_for_token)
    print()
    access_token=get_ctr_token(host_for_token,ctr_client_id,ctr_client_password)
    print()
    print(yellow("- > Create Incident JSON and incident_xid",bold=True))
    print()                  
    incident_json,incident_xid=create_incident_json_for_ftd_alerts(incident_title)
    incidents=[]
    incidents.append(json.loads(incident_json))        
    print()
    print('incident_json : ',yellow(incident_json,bold=True))    
    print()
    print('incident_xid : ',yellow(incident_xid,bold=True))                
    print()
    sightings=[]
    relationships_new=[]
    global indicator_list # You must have already created an Indicator and a feed attached to it ( ex : Indicator name : Web_Attacks_IPv4  and Feed Name : Web_Attack_Feed
    for this_sighting in all_sightings:    
        print()
        print(' this sighting : \n',cyan(this_sighting,bold=True))
        
        print()   
        print(magenta('--> CALL  A SUB FUNCTION :',bold=True))   
        sighting_xid = create_sighting_xid("Sighting created for asset enrichment test")
        sighting_transient_id="transient:"+sighting_xid
        print("  - This Sighting_transient_id : ",cyan(sighting_transient_id,bold=True))
        print("  - Create This Sighting json payload with : ",cyan(sighting_transient_id,bold=True))
        print()   
        print(magenta('--> CALL  A SUB FUNCTION :',bold=True))               
        new_sighting_id,sighting=create_sighting_json(sighting_xid,this_sighting)
        sightings.append(json.loads(sighting)) # adding this sighting to sighting list
        print('   -- ok done')                    
        print()
        print(yellow("- > Create Relationship payload for sighting to Indicator relationship",bold=True))
        print()                
        print('indicator_list :\n',cyan(indicator_list,bold=True))              
        for indicator in indicator_list:
            the_new_indicator_id=indicator.split('***')[0]
            print()
            print('--- OK lets create the indicator relationship')
            print()                
            print('new indicator id :\n',cyan(the_new_indicator_id,bold=True)) 
            #CALL  A SUB FUNCTION
            print()   
            print(magenta('--> CALL  A SUB FUNCTION :',bold=True))   
            nombre=random.randint(1, 10)                 
            random_xid=id_generator(nombre, "6793YUIO")     
            #CALL  A SUB FUNCTION
            print()   
            print(magenta('--> CALL  A SUB FUNCTION :',bold=True))                     
            relationship_xid=generate_relationship_xid(the_new_indicator_id,random_xid)
            print('relationship_xid : ',cyan(relationship_xid,bold=True))
            #CALL  A SUB FUNCTION
            print()   
            print(magenta('--> CALL  A SUB FUNCTION :',bold=True))                     
            relationship=create_relationship_object(sighting_transient_id,the_new_indicator_id,relationship_xid,"sighting-of","XDR Side Car")   
            relationships_new.append(json.loads(relationship)) # adding this relationship to  relationship list    
        print(yellow("- > Create Relationship payload for sighting to Incident memberships. Sighting is member-of Incident",bold=True))
        print(magenta('--> CALL  A SUB FUNCTION :',bold=True))      
        nombre=random.randint(1, 10)                 
        random_xid=id_generator(nombre, "6723YUIO")        
        relationship_xid=generate_relationship_xid(sighting_transient_id,random_xid)
        print()   
        print(magenta('--> CALL  A SUB FUNCTION :',bold=True))                  
        relationship=create_relationship_object(sighting_transient_id,incident_xid,relationship_xid,"member-of","Custom_Syslog_Server")    
        relationships_new.append(json.loads(relationship)) # adding this relationship to  relationship list   
    print()
    print(' sightings :\n ',yellow(sightings,bold=True))
    print()
    print(' relationships :\n ',yellow(relationships_new,bold=True))
    print()
    print(yellow("- create a judgment JSON payload for the ip source",bold=True))
    judgments_new=[]
    add_a_jugdment_for_source_ip=1 # we create a judgment for the source IP address
    if add_a_jugdment_for_source_ip:
        judgments_new.append(generate_judgment_json(ip_source))
        print()
        print(' judgments_new :\n ',yellow(judgments_new,bold=True))
        print()   
        print(yellow("- OK Done ",bold=True))  
        print()
        print(yellow("- Now add a relationship for this judgment to related indicator",bold=True))
        indicator_id=get_indicator_id_for_ips_sightings(indicator_list[0]) 
        relationship_xid=generate_relationship_xid(judgments_new[0]['id'],indicator_id)   
        relationship_object={}    
        relationship_object = create_relationship_object(judgments_new[0]['id'], indicator_id, relationship_xid, "element-of","Custom_Syslog_Server")
        print()
        print(' relationship_object :\n ',yellow(relationship_object,bold=True))
        print() 
        relationships_new.append(json.loads(relationship_object)) # adding this relationship to  relationship list   
    print()
    print(' relationships :\n ',yellow(relationships_new,bold=True))
    print()  
    print(yellow("- OK Done ",bold=True))  
    print()    
    source_for_bundle="Custom_Syslog_Server"
    print()
    print(yellow("- Step 6 create Bundle JSON payload => Put everything together",bold=True))    
    #incidents=[]
    indicators=[]
    #relationships_new=[]        
    print()   
    print(magenta('--> CALL  A SUB FUNCTION :',bold=True))           
    bundle=create_bundle_json(source_for_bundle,incidents,sightings,indicators,judgments_new, relationships_new)
    print()
    print(yellow("  - Ok Bundle JSON payload is ready",bold=True))
    print()
    print(yellow(" OKAY Ready to create the Incident In destination XDR tenant",bold=True))
    print()
    print(yellow("Step 7 Let's go !",bold=True))
    print()
    print('BUNDLE TO BE SENT is bellow :\n')
    bundle_in_json=json.dumps(bundle,indent=4,sort_keys=True, separators=(',', ': '))
    print(cyan(bundle_in_json,bold=True))  
    print()
    print('OK NOW POST THE BUNDLE TO XDR :\n')
    resultat=post_bundle(host_for_token,access_token,bundle_in_json)  
    print(' Bundle API call result : \n',green(resultat,bold=True))
    return(resultat)

#
# Here under FTD syslog parsing 
#
def current_date_time():
    '''
        current time in the YYYY-mm-ddTH:M:S.fZ format
    '''
    print()
    print(green('.. def current_date_time() : >',bold=True))
    print()
    current_time = datetime.utcnow()
    current_time = current_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return(current_time)
    
def current_date_and_time_for_filename():  
    print()
    print(green('.. def current_date_and_time_for_filename() : >',bold=True))
    print() 
    '''
        current time + nb days in the YYYYmmddHM format
    '''
    current_time = datetime.utcnow()
    #timestampStr = current_time.strftime("%Y%m%d%H%M%S")
    timestampStr = current_time.strftime("%Y%m%d%H%M")
    return(timestampStr)
    
def current_date_and_time_for_filename_plus():  
    print()
    print(green('.. def current_date_and_time_for_filename_plus() : >',bold=True))
    print() 
    '''
        current time + nb days in the YYYYmmddHMSf format
    '''
    current_time = datetime.utcnow()
    #timestampStr = current_time.strftime("%Y%m%d%H%M%S")
    timestampStr = current_time.strftime("%Y%m%d%H%M%S%f")
    return(timestampStr)
    
def parse_ftd_single_log(syslog): 
    print()
    print(green('def parse_ftd_single_log() : >',bold=True))
    print()
    print('syslog : \n',yellow(syslog,bold=True))
    log={}
    fields=syslog.split(',')
    #new_line=fields[0]+','+fields[4]+','+fields[5]+','+fields[6]+','+fields[7]+','+fields[8]+','+fields[13]+','+fields[17]+','+fields[18]+','+fields[19]+','+fields[20]
    #print(cyan(new_line,bold=True))
    timestamp=fields[0].split('  :')[0]
    timestamp=timestamp.split('>')[1]            
    DeviceUUID=fields[0].split(': ')[3]
    SrcIP=fields[4].split(': ')[1]
    DstIP=fields[5].split(': ')[1]
    SrcPort=fields[6].split(': ')[1]
    DstPort=fields[7].split(': ')[1]
    Protocol=fields[8].split(': ')[1]
    Priority=fields[13].split(': ')[1]
    Message=fields[17].split(': ')[1]
    Classification=fields[18].split(': ')[1]
    Client=fields[19].split(': ')[1]
    ApplicationProtocol=fields[20].split(': ')[1]
    log['timestamp']=timestamp
    log['DeviceUUID']=DeviceUUID
    log['SrcIP']=SrcIP
    log['DstIP']=DstIP
    log['SrcPort']=SrcPort
    log['DstPort']=DstPort
    log['Protocol']=Protocol
    log['Priority']=Priority           
    log['Message']=Message            
    log['Classification']=Classification
    log['Client']=Client
    log['ApplicationProtocol']=ApplicationProtocol
    print(red('< ALERT ! >\n',bold=True), timestamp,' From ',green(SrcIP,bold=True),' to => ',cyan(DstIP,bold=True),'\n',yellow(Message,bold=True),'\n',Priority)
    #print(yellow(log,bold=True))
    return(log)

def create_a_sighting_json(log):
    print()
    print(green('def create_a_sighting_json() : >',bold=True))
    print()
    sighting={}
    #log_json=json.loads(log)
    date_and_time=current_date_time()
    observables=[{"value": log['SrcIP'],"type": "ip"},{"value": log['DstIP'],"type": "ip"}]
    relations=[
    {
      "relation": "Connected_To",
      "origin":"FTD Syslog server",
      "source": {
        "value": log['SrcIP'],
        "type": "ip"
      },
      "related": {
        "value": log['DstIP'],
        "type": "ip"
      }
    }
  ]
    targets= [
    {
      "type": "endpoint",
      "observables": [
        {
          "value": log['DstIP'],
          "type": "ip"
        }
      ],
      "observed_time": {
        "start_time": date_and_time,
        "end_time": date_and_time
      }
    }
  ]
    observed_time = {
    "start_time": date_and_time,
    "end_time": date_and_time
  }
    if log['Priority']=="1":
       sighting['severity']="Critical"
    elif log['Priority']=="2":
       sighting['severity']="High"
    elif log['Priority']=="3":
       sighting['severity']="Medium"    
    else: 
       sighting['severity']="Low"         
    sighting['observables']=observables
    sighting['relations']=relations
    sighting['source']="Custom_Syslog_Server"
    sighting['targets']=targets
    sighting["short_description"]=log['Message']
    sighting["title"]="IPS Alert SrcIP : "+log['SrcIP']+' to DstIP : '+log['DstIP']
    sighting["confidence"]= "High"
    sighting["observed_time"]= observed_time
    sighting["sensor"]= "network.firewall"
    sighting["description"]= "Network IPS Alert : "+log['Classification']+', between SrcIP : '+log['SrcIP']+' SrcPort : '+log['Protocol']+'/'+log['SrcPort']+' To DstIP : '+log['DstIP']+' DstPort : '+log['Protocol']+'/'+log['DstPort']+', Client : '+log['Client']+', Application : '+log['ApplicationProtocol']
    print()
    print(cyan(sighting,bold=True))
    print()
    print(red('< END > ',bold=True))
    #
    # Save sighting ? ( for futur additionnal correlation with futur detections )
    #
    if save_sightings:
        sighting_path='./sighting_library/sighting-FTD_'+current_date_and_time_for_filename_plus()+'_.json'
        with open(sighting_path,'w') as f:
            text_out=json.dumps(sighting)
            f.write(text_out)
    #
    # ==========
    #
    incident_key=log['SrcIP']+'_to_'+log['DstIP']
    if incident_key not in incidents.keys():
        incidents[incident_key]=[]
        incidents[incident_key].append(sighting)
        incidents_counts[incident_key]=0
    else:
        incidents[incident_key].append(sighting)
        incidents_counts[incident_key]+=1
        
    if incidents_counts[incident_key]>10:
        incident_title="Secure Firewall IPS Alerts for Src : "+log['SrcIP']+" to Dst : "+log['DstIP']
        result=create_an_xdr_incident(incidents[incident_key],log['SrcIP'],incident_title)
        incidents[incident_key].clear()
        incidents_counts[incident_key]=0  
        print('result : ',result)
        if result:
            incidents[incident_key].clear()
            incidents_counts[incident_key]=0
            print(green('Incident saved . Waiting for next log ',bold=True))
            print()
            return 1
        else:
            print(red('something failed. Incident not posted into XDR ',bold=True))
            
def check_if_feed_exists():
    print()
    print(green('.. def check_if_feed_exists() : >',bold=True))
    print() 
    '''
    Check if feed named : syslog_server_feed exits within XDR
    if the answer is yes the retreive the indicator id
    If the answer is no then create it and create an attached indicator named : syslog_server_alerts
    '''
    # ASKING FOR A TOKEN TO XDR TENANT
    method="config.txt"
    if method=="config.txt":
        with open('./keys/config.txt','r') as file:
            text_content=file.read()
    ctr_client_id,ctr_client_password,host_for_token,host,profil_name = parse_config(text_content)
    # print()       
    # print('ctr_client_id :',ctr_client_id)
    # print('ctr_client_password :',ctr_client_password)
    # print('host : ',host )
    # print('host_for_token : ',host_for_token)
    # # print()
    access_token=get_ctr_token(host_for_token,ctr_client_id,ctr_client_password)
    # print(yellow('--> Let check if indicator named : syslog_server_alerts exists',bold=True))
    global indicator_list
    # print()
    indic_list=get_indicators(host,access_token)
    # print()
    # print(' indic_list :\n ',cyan(indic_list,bold=True))
    indic_dict={} 
    i=0
    for item in indic_list:
        # print(' item :\n ',cyan(item,bold=True))
        # print()
        # print(' item type :\n ',cyan(type(item),bold=True))
        # print()
        keyword="syslog_server_alerts"
        found=0
        for k,v in item.items():
            if keyword in k:
                indic_dict[i]={"title":k,"indicator_id":v} 
                # print()
                # print(green('syslog_server_alerts Indicator exist',bold=True))
                indicator_list.append(v+'***xxx')
                found=1  
    if found==0:
        print()
        print(red('Indicator does NOT exist. Let\'s create it',bold=True))  
        indicator_name="syslog_server_alerts"
        indicator_type="IPv4"
        description="Indicator for IPv4 addresses that had been seen sending attack to Destination IP addresses into FTD IPS Alerts"
        indicator_id=create_indicator(host,access_token,indicator_name,indicator_type,description)
        indicator_list.append(indicator_id+'***xxx')
    # print()
    # print(' indicator_list :\n ',cyan(indicator_list,bold=True))
    # print()          
    print(yellow('--> Let check if feed named : syslog_server_feed exists',bold=True))
    print()                
    feed_list=get_feeds(host,access_token)
    feed_name="syslog_server_feed"
    found=0
    for item in feed_list:
        if feed_name==item['title']:   
            print()
            print(green('syslog_server_feed feed exists',bold=True))
            found=1
    if found==0:
        print()
        print(red('Feed does NOT exist. Let\'s create it',bold=True)) 
        feed_id=create_feed(host,access_token,indicator_id,feed_name)
        print()
        print(' feed_id :\n ',cyan(feed_id,bold=True))
        print()       
# here under syslog server functions
class SyslogUDPHandler(socketserver.BaseRequestHandler):

    def handle(self):
        # get syslog message receive in the socket
        data = bytes.decode(self.request[0].strip())
        socket = self.request[1]
        syslog=str(data) # put it into the syslog variable
        # ok here under let's do basic parsing and let's keep only FTD IPS alerts BUT dont keep syslogs with 'PROTOCOL-DNS SPOOF query response with TTL of 1 min. and no authority'
        if '%FTD' in syslog and 'SID' in syslog and 'PROTOCOL-DNS SPOOF query response with TTL of 1 min. and no authority' not in syslog:
            the_log=parse_ftd_single_log(syslog)
            create_a_sighting_json(the_log)            

if __name__ == "__main__":
    check_if_feed_exists()
    if indicator_list==[]:
        print(red('In XDR : You must create first an indicator with Indicator name : Web_Attacks_IPv4  and a feed with Feed Name : Web_Attack_Feed !. Then update the indicator_list variable at the top of this file with the Indicator ID value ', bold=True))
        sys.exit()
    try:
        print()
        print(' Let\'s start Syslog Server - listening on UDP 514')
        print()
        print(f'   attached Indicator is : \n    {indicator_list}')
        print()
        print(green(' All Good - listening on UDP 514 waiting for syslog messages',bold=True))
        print()
        print()
        server = socketserver.UDPServer((HOST,PORT), SyslogUDPHandler)
        server.serve_forever(poll_interval=0.5)        
    except (IOError, SystemExit):
        raise
    except KeyboardInterrupt:
        print ("Crtl+C Pressed. Shutting down.")