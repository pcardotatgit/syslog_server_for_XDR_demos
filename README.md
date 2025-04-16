# Syslog Server for XDR demos and Labs

This project is is a proof of concept of a syslog server that is able to create Incidents and Sightings within XDR.

It serves as an example of use case to use during Cisco XDR Incidents APIs workshops.

It is was not made for production just for training. But it has strong capabilities in terms of number of syslogs messages captured per second.

This is a very straight forward syslog server written in python. It listens on UDP port 514 only. 

This is a perfect tool to use into a lab infrastructure into which you have something like 20 / 30 devices that send syslogs alerts.

It doesn't store syslogs messages. It only monitor some specific messages in the goal to create Incidents into XDR.

It contains a very basic parser that analyse every syslog messages received. Track some specific messages and create an XDR Incident when 10 syslog Alerts that involve same sources and destinations are received.

The parsing example contained into the application parses only Cisco Secure Firewall IPS syslogs and Web Attacks. This just what we need for a training.

The parser can be extended in order to extended the detection capabilities. 

The project contains as well a syslog message generator that send Cisco Secure Firewall IPS syslogs. Just to avoid to deploy a real FTD infra in a workshop context.  We don't need the infrastructure, we just need the syslog messages this infra could generate.

# Installation

## Prerequisit

You must start with a machine that already has python installed. This project was written in python 3.11 version but should work with python 3.10.

An XDR tenant and an API Client created into it ( client_id and client_password )

## Very fast install for windows users

For anyone who don't want to waste time.

Download the project into a working directory into your laptop. Unzip the dowloaded file and open a terminal console into the project root directory. Then

- type a
- then type b
- then type c
- then type d
- finally type e

Edit the **./keys/config.py** file

ok now you can run the syslog server by typing

- first  : type a
- second : type b

DONE : the syslog server starts

## Here under the step by step installation if you don't use the procedure just above

## Step 1. Create a working directory

Create a working directory into your laptop. Open a terminal CMD window into it. Name It XDR_BOT for example.

## Step 2. Copy the code into your laptop

The Download ZIP Method

The easiest way for anyone not familiar with git is to copy the ZIP package available for you in this page. Click on the Code button on the top right of this page. And then click on Download ZIP.

Unzip the zip file into your working directory.

The "git clone" method with git client

And here under for those of you who are familiar with Github.

You must have a git client installed into your laptop. Then you can type the following command from a terminal console opened into your working directory.

    git clone https://github.com/pcardotatgit/webex_for_xdr_part-5_websocket.git

## Step 3. Go to the code subfolder

Once the code unzipped into your laptop, then Go to the code subfolder.

## Step 4. Create a Python virtual environment

It is still a best practice to create a python virtual environment. Thank to this you will create a dedicated package with requested modules for this application. 

### Create a virtual environment on Windows

    python -m venv venv 

### Create a virtual environment on Linux or Mac

    python3 -m venv venv

Depending on the python version you installed into your Mac you might have to type either 

- python -m venv venv

or maybe

- python3 -m venv venv    : python3 for python version 3.x  

or maybe 

- python3.9 -m venv venv  : if you use the 3.9 python version

And then move to the next step : Activate the virtual environment.

### Activate the virtual environment on Windows

    venv\Scripts\activate

### Activate the virtual environment on Linux or Mac

    source venv/bin/activate    

## Step 5. Install needed python modules

You can install them with the following 2 commands one after the other ( Windows / Mac / Linux ):

The following command might be required if your python version is old.

    python -m pip install --upgrade pip   

Then install required python modules ( Windows / Mac / Linux )

    pip install -r requirements.txt
    
## Step 6. Initial setup

Edit the **config.py** file which contains initialization variables :

```
{
profil_name=ANY_NAME
ctr_client_id=xxx
ctr_client_password=xxx
host=https://private.intel.eu.amp.cisco.com
host_for_token=https://visibility.eu.amp.cisco.com
}
```

**ctr_client_id** and **ctr_client_password** are the credentials you got when you created your XDR API client.

Depending on your region use the correct XDR fqdn !

## Step 7 : run the syslog server

    python syslog_server.py
    
## Step 8 - Test the syslog server

Use the [syslog_message_generator](https://github.com/pcardotatgit/syslog_message_generator) to quickly test your setup