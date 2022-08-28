#!python3

from flask import Flask
import json
import requests
import re

app = Flask(__name__)

NETBOX_PATH = "http://127.0.0.1:8000/api"
DOMAIN_SUFFIX = "network.local"
NETBOX_HEADERS = {'Accept': 'application/json', 'Authorization': 'Token 0123456789abcdef0123456789abcdef01234567'}

@app.route("/getAllDomains")
def all_domains():
    data = {"result":[
        {"id":1,"zone":"in-addr.arpa.","masters":["127.0.0.1"],"notified_serial":1,"serial":1,"last_check":0,"kind":"native"}
    ]}
    return json.dumps(data)

@app.route("/getUpdatedMasters")
def updated_masters():
    return json.dumps({"result": []})

@app.route("/getAllDomainMetadata/<string:domain>")
def get_domain_metadata(domain):
    return json.dumps({"result": []})

@app.route("/lookup/<string:host>/<path:method>")
def hello_world(host, method):
    results = []

    if method == "SOA" or method == "ANY":
        results.append({'ttl': 60, 'auth': 1, 'qname': host, 'qtype': 'SOA',
         'content': 'dynamically-generated.local. nobody.local. 1 3600 3600 3600 60'})

    #100.0.168.192.in-addr.arpa.
    request_parts = host.split(".")
    if (len(request_parts) == 7 or len(request_parts) == 6) and "in-addr.arpa" in host:
        #ipv4 reverse lookup
        ip_address = request_parts[3] + "." + request_parts[2] + "." + request_parts[1] + "." + request_parts[0]
        ip_host = get_ip_hostname_from_netbox(ip_address)
        ip_details = get_ip_details_from_ip(ip_address)

        results.append({'ttl': 60, 'auth': 1, 'qname': host, 'qtype': 'PTR', 'content': ip_host})
        results.append({'ttl': 60, 'auth': 1, 'qname': host, 'qtype': 'TXT', 'content': ip_details})

    return json.dumps({'result': results})

def get_device_name_from_id(id):
    http_request = requests.get(f"{NETBOX_PATH}/dcim/devices/{id}/?format=json", headers=NETBOX_HEADERS)
    if http_request.status_code == 200:
        data = json.loads(http_request.content)

        display_name = data['display']
        site_slug = data['site']['slug']

        if 'DNS_Slug' in data['custom_fields'].keys() and data['custom_fields']['DNS_Slug'] is not None and len(data['custom_fields']['DNS_Slug']) > 0:
            dns_slug = data['custom_fields']['DNS_Slug']
            return f"{dns_slug}.{site_slug}.{DOMAIN_SUFFIX}".lower()
        else:
            display_name = re.sub(r'[^A-za-z0-9\-]*', '', display_name)
            return f"{display_name}.{site_slug}.{DOMAIN_SUFFIX}".lower()
    else:
        return "unknown.unknown"

def get_device_text_from_id(id):
    http_request = requests.get(f"{NETBOX_PATH}/dcim/devices/{id}/?format=json", headers=NETBOX_HEADERS)
    if http_request.status_code == 200:
        data = json.loads(http_request.content)

        display_name = data['display']
        site_name = data['site']['display']
        device_model = data['device_type']['display']
        device_make = data['device_type']['manufacturer']['display']

        return f"{display_name} ({device_make} {device_model}) at {site_name}"
    else:
        return "Unknown"

def get_ip_hostname_from_netbox(ip):
    http_request = requests.get(f"{NETBOX_PATH}/ipam/ip-addresses/?format=json&address={ip}", headers=NETBOX_HEADERS)
    if http_request.status_code == 200:
        data = json.loads(http_request.content)
        if 'count' in data.keys() and data['count'] is not None and data['count'] == 1:
            result = data['results'][0]
            if result['assigned_object_type'] == "dcim.interface":
                interface_name = result['assigned_object']['display']
                device_id = result['assigned_object']['device']['id']

                interface_name = interface_name.replace("/", "-").lower()
                interface_name = interface_name.replace("tengigabitethernet", "te")
                interface_name = interface_name.replace("gigabitethernet", "ge")
                interface_name = interface_name.replace("fastethernet", "fa")
                interface_name = interface_name.replace("ethernet", "e")
                interface_name = interface_name.replace("loopback", "lo")
                interface_name = interface_name.replace("port-channel", "po")
                interface_name = interface_name.replace("portchannel", "po")
                interface_name = interface_name.replace("vlan", "v")
                interface_name = interface_name.replace("management", "m")
                interface_name = interface_name.replace("serial", "s")
                interface_name = interface_name.replace("lan", "e")

                device_host = get_device_name_from_id(device_id)
                return f"{interface_name}--{device_host}".lower()
            else:
                description = result['description']
                description = re.sub(r'[^A-za-z0-9\-]*', '', description)
                return f"{description}.unknown.{DOMAIN_SUFFIX}".lower()
        else:
            return "unknown.unknown"
    else:
        return "unknown.unknown"

def get_ip_details_from_ip(ip):
    http_request = requests.get(f"{NETBOX_PATH}/ipam/ip-addresses/?format=json&address={ip}", headers=NETBOX_HEADERS)
    if http_request.status_code == 200:
        data = json.loads(http_request.content)
        if 'count' in data.keys() and data['count'] is not None and data['count'] == 1:
            result = data['results'][0]
            if result['assigned_object_type'] == "dcim.interface":
                interface_name = result['assigned_object']['display']
                device_id = result['assigned_object']['device']['id']

                base_description = get_device_text_from_id(device_id)

                return f"{interface_name} on {base_description}"
            else:
                description = result['description']
                return f"{description}"
        else:
            return "Unknown"
    else:
        return "Unknown"
