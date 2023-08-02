import os
import uuid
import json
import oyaml as yaml
import datetime
import re

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
                    "description": [],
                    "references": [],
                    "author": "@mthcht",
                    "date": "2023/07/30",
                    "modified": formatted_time,
                    "tags": [],
                    "logsource": {
                        "category": []
                    },
                    "falsepositives": ["Unknown"],
                    "level": [],
                    "detection": {
                        "selection": {}
                    },
                    "fields": []
                }

                for item in data:
                    fields =[]

                    # Add techniques and tactics
                    sigma_rule['tags'].extend(["attack." + tactic for tactic in item['tactics'].split(' - ')])
                    sigma_rule['tags'].extend(["attack." + technique for technique in item['techniques'].split(' - ')])

                    # Add descriptions
                    sigma_rule['description'].append("\'" + item['description'] + "\'")
                    
                    # Add links
                    sigma_rule['references'].append(item['reference'])
                    
                    # Add severity
                    sigma_rule['level'].append(get_level(item['severity'],item['popularity']))
                    
                    if item['endpoint_detection']:
                        if identify_hash(item['keyword']) == "yes":
                            fields += endpoint_hash_fields
                        else:
                            if any(substring in item['keyword'] for substring in [' --', ' ../',' ..\\']) or item['keyword'].count(' ') > 1:
                                fields += endpoint_detection_fields_space # endpoint fields allowing spaces
                                sigma_rule['logsource']['category'].append('endpoint')
                            else:
                                fields += endpoint_detection_fields # add all endpoint fields
                                sigma_rule['logsource']['category'].append('endpoint')

                    if item['network_detection']:
                        fields += network_detection_fields
                        sigma_rule['logsource']['category'].append('network')

                    for field in fields:
                        if field not in sigma_rule['detection']['selection']:
                            sigma_rule['detection']['selection'][field] = []
                        sigma_rule['detection']['selection'][field].append(item['keyword'])
                        if field not in sigma_rule['fields']:
                            sigma_rule['fields'].append(field)


                sigma_rule['detection']['condition'] = 'selection'
                
                # remove duplicates
                sigma_rule['logsource']['category'] = list(set(sigma_rule['logsource']['category']))
                sigma_rule['description'] = list(set(sigma_rule['description']))
                sigma_rule['references'] = list(set(sigma_rule['references']))
                sigma_rule['level'] = list(set(sigma_rule['level']))
                sigma_rule['tags'] = list(set(sigma_rule['tags']))
                # sort
                sigma_rule['tags'].sort(key=lambda s: s.lower())
                sigma_rule['description'].sort(key=lambda s: s.lower())
                sigma_rule['references'].sort(key=lambda s: s.lower())
                sigma_rule['level'].sort(key=lambda s: s.lower())
                sigma_rule['logsource']['category'].sort(key=lambda s: s.lower())


                # Save the sigma_rule to a .yml file in the same directory as the JSON file
                with open(os.path.join(subdir, file.replace(".json", ".yml")), 'w') as yaml_file:
                    yaml.dump(sigma_rule, yaml_file, default_flow_style=False)