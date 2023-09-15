import os
import uuid
import json
import oyaml as yaml
import datetime
import re

yaml.Dumper.ignore_aliases = lambda *args : True

# Fields (add or modify the fields variables with your fields)
endpoint_detection_fields = ['Image', 'OriginalFileName','CurrentDirectory','ParentImage','ParentCommandLine','TargetFilename','Signature','signature','ImageLoaded','Company','Description','description','CommandLine','SourceImage','TargetImage','CallTrace','TargetObject','Details','PipeName','Consumer','Destination','Name','Query','NewName','StartAddress','StartModule','StartFunction','SourceHostname','Device','file_name','file_path','process','original_file_name','parent_process','process_path','service_path','registry_path','registry_value_data','registry_value_name','ContextInfo','Payload','ScriptBlockText','ServerName','TransportName','NewProcessName','ParentProcessName','Application','Product Name','Threat Name','Process Name','Path','ImagePath','ServiceName','ProcessPath','AppName','AppPath','ModulePath','registry.data.strings','registry.path','registry.value','process.args','process.command_line','process.env_vars','process.io.text','process.executable','process.name','process.title','pe.company','pe.description','pe.original_file_name','pe.product','os.full','host.hostname','file.fork_name','file.name','file.path','file.target_path','email.attachments.file.name','email.subject','dll.path','device.model.name','container.image.name','container.name','object']
endpoint_detection_fields_space = ['ParentCommandLine','CommandLine','Details','registry.value','process.args','process.command_line','process.env_vars','process.io.text','process.title','pe.company','pe.description','pe.product','os.full','host.hostname','event.original','email.subject','device.model.name','container.image.name','container.name']
endpoint_hash_fields = ['Hashes','file_hash','hash.md5','hash.sha1','hash.sha256','hash.sha384','hash.sha512','hash.ssdeep','service_hash','description']
network_detection_fields = ['url','dest_url','uri','uri_query','query','url_domain','uri_path','domain','QueryName','QueryResults','DestinationHostname','DestinationIp','http_referrer','http_referrer_domain','http_user_agent','dest_nt_host','sender','recipient','orig_recipient','subject','url.domain','url.full','url.original','url.query','user_agent.original','network.application','http.request.body.content','http.request.referrer','email.from.address','dns.question.name','destination.domain']
# event.original or _raw can be added for raw log searches

def get_level(severity,popularity):
    if severity.isdigit() and popularity.isdigit():
        severity = int(severity)
        popularity = int(popularity)
        if 9 <= severity <= 10 and popularity >= 9:
            return "critical"
        elif 9 <= severity <= 10 and popularity < 9:
            return "high"
        elif 6 <= severity <= 8 and popularity > 1:
            return "medium"
        elif 5 <= severity <= 8 and popularity <= 1:
            return "low"
        elif 4 <= severity < 6 and popularity == 10:
            return "medium"
        else:
            return "low"
    else:
        return "Unknown"

def identify_hash(string):
    md5_re = re.compile(r'\b([a-fA-F\d]{32})\b')
    sha1_re = re.compile(r'\b([a-fA-F\d]{40})\b')
    sha256_re = re.compile(r'\b([a-fA-F\d]{64})\b')
    if md5_re.search(string) or sha1_re.search(string) or sha256_re.search(string):
        return "yes"
    else:
        return "no"

# Get root directory
current_directory = os.path.dirname(os.path.realpath(__file__))
parent_directory = os.path.dirname(current_directory)

# Walk through each directory and file
for subdir, dirs, files in os.walk(parent_directory):
    for file in files:
        if file.endswith(".json"):
            with open(os.path.join(subdir, file), 'r') as json_file:
                data = json.load(json_file)

                # Get rule id
                yml_file_path = os.path.join(subdir, os.path.splitext(file)[0] + '.yml')
                if os.path.isfile(yml_file_path):
                    with open(yml_file_path, 'r') as yml_file:
                        yml_content = yaml.safe_load(yml_file)
                        existing_id = yml_content['id']
                        if existing_id:
                            id = existing_id
                        else:
                            # Generate a unique ID
                            id = str(uuid.uuid4())
                else:
                    # Generate a unique ID
                    id = str(uuid.uuid4())

                # Get date
                current_time = datetime.datetime.now()
                formatted_time = current_time.strftime('%Y/%m/%d')

                sigma_rule = {
                    "title": "Simple keyword detection rule for {}".format(data[0]['tool_name']),
                    "id": id,
                    "status": "experimental",
                    "description": "Detects interesting keywords based on {} tool".format(data[0]['tool_name']),
                    "references": [],
                    "author": "@mthcht",
                    "date": "2023/07/30",
                    "modified": formatted_time,
                    "tags": [],
                    "logsource": {
                        "category": []
                    },
                    "detection": {
                        "selection": []
                    },
                    "fields": [],
                    "falsepositives": ["unknown"],
                    "level": 'medium'
                }
                # setting medium level for all the hunting rules instead of using get_level function

                # We use these bools to avoid duplication when choosing the fields
                endpoint_hash_fields_bool = False
                endpoint_detection_fields_space_bool = False
                endpoint_detection_fields_bool = False
                network_detection_fields_bool = False
                
                # We use these bools to assign category only once
                endpoint_rule = False
                network_rule = False

                endpoint_keywords_list = []
                network_keywords_list = []

                network_fields = []
                endpoint_fields = []

                for item in data:

                    # Add techniques and tactics
                    tactic = ["attack." + tactic for tactic in item['tactics'].split(' - ')]
                    technique = ["attack." + technique for technique in item['techniques'].split(' - ')]

                    if tactic not in sigma_rule['tags'] and tactic != "N/A":
                        sigma_rule['tags'].extend(tactic)

                    if technique not in sigma_rule['tags'] and technique != "N/A":
                        sigma_rule['tags'].extend(technique)
                    
                    # Add links
                    if item['reference'] != "N/A":
                        sigma_rule['references'].append(item['reference'])
                    
                    # Assign the fields
                    if item['endpoint_detection']:

                        endpoint_keywords_list.append(item['keyword'])

                        if identify_hash(item['keyword']) == "yes":
                            if not endpoint_hash_fields_bool:
                                endpoint_fields += endpoint_hash_fields
                                endpoint_hash_fields_bool = True
                            if not endpoint_rule:
                                sigma_rule['logsource']['category'].append('endpoint')
                                endpoint_rule = True
                        else:
                            if any(substring in item['keyword'] for substring in [' --', ' ../',' ..\\']) or item['keyword'].count(' ') > 1:
                                if not endpoint_detection_fields_space_bool:
                                    endpoint_fields += endpoint_detection_fields_space # endpoint fields allowing spaces
                                    endpoint_detection_fields_space_bool = True
                                if not endpoint_rule:
                                    sigma_rule['logsource']['category'].append('endpoint')
                                    endpoint_rule = True
                            else:
                                if not endpoint_detection_fields_bool:
                                    endpoint_fields += endpoint_detection_fields # add all endpoint fields
                                    endpoint_detection_fields_bool = True
                                if not endpoint_rule:
                                    sigma_rule['logsource']['category'].append('endpoint')
                                    endpoint_rule = True

                    if item['network_detection']:

                        network_keywords_list.append(item['keyword'])

                        if not network_detection_fields_bool:
                            network_fields += network_detection_fields
                            network_detection_fields_bool = True
                        if not network_rule:
                            sigma_rule['logsource']['category'].append('network')
                            network_rule = True
                    
                    
                # Add Keywords to SIGMA rule
                if endpoint_keywords_list:
                    for epf in endpoint_fields:
                        final_detection = {}
                        final_detection[epf] = endpoint_keywords_list
                        sigma_rule['detection']['selection'].append(final_detection)
                
                if network_keywords_list:
                    for nf in network_fields:
                        final_detection = {}
                        final_detection[nf] = network_keywords_list
                        sigma_rule['detection']['selection'].append(final_detection)
                    
                sigma_rule['fields'] = endpoint_fields + network_fields
                sigma_rule['detection']['condition'] = 'selection'
                
                # remove duplicate
                sigma_rule['tags'] = list(set(sigma_rule['tags']))
                if 'attack.N/A' in sigma_rule['tags']:
                    sigma_rule['tags'].remove('attack.N/A')
                # sort
                sigma_rule['tags'].sort(key=lambda s: s.lower())
                # remove duplicate
                sigma_rule['references'] = list(set(sigma_rule['references']))
                sigma_rule['references'].sort(key=lambda s: s.lower())
                
                sigma_rule['logsource']['category'].sort(key=lambda s: s.lower())

                # Save the sigma_rule to a .yml file in the same directory as the JSON file
                with open(os.path.join(subdir, file.replace(".json", ".yml")), 'w') as yaml_file:
                    yaml.dump(sigma_rule, yaml_file, default_flow_style=False)
