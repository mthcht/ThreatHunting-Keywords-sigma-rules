import csv
import json
import os

def sanitize_filename(name):
    return "".join([c if c.isalnum() else "_" for c in name])

tools = {}

filename = 'threathunting-keywords.csv'
if os.path.isfile(filename):
    with open(filename, 'r') as f:
        reader = csv.DictReader(f)
        # Iterate over the rows
        for row in reader:
            keyword = row['keyword'].strip()
            if not keyword:  # Skip empty keyword rows
                continue

            tool_name = sanitize_filename(row['metadata_tool'])

            # Create a dictionary for this tool if it doesn't exist
            if tool_name not in tools:
                tools[tool_name] = {
                    "type": row['metadata_keyword_type'],
                    "data": []
                }

            # Add the row data for this keyword
            tools[tool_name]["data"].append({
                "keyword": keyword,
                "description": row['metadata_description'],
                "tool_name": row['metadata_tool'],
                "reference": row['metadata_link'],
                "severity": row['metadata_severity_score'],
                "popularity": row['metadata_popularity_score'],
                "keyword_type": row['metadata_keyword_type'],
                "comment": row['metadata_comment'],
                "tactics": row['metadata_tool_tactics'],
                "techniques": row['metadata_tool_techniques'],
                "endpoint_detection": bool(int(row['metadata_enable_endpoint_detection'])),
                "network_detection": bool(int(row['metadata_enable_proxy_detection'])),
            })
else:
    print(f"File {filename} does not exist.")
    exit(1)

# Now write out the data for each tool
for tool_name, tool_data in tools.items():
    # Define tool directory based on keyword type
    if tool_data["type"] == "offensive_tool_keyword":
        tool_directory = 'offensive_tools'
    elif tool_data["type"] == "greyware_tool_keyword":
        tool_directory = 'greyware_tools'
    elif tool_data["type"] == "signature_keyword":
        tool_directory = 'signatures'
    else:
        continue  # Skip if type is unrecognized

    os.makedirs(os.path.join('..', 'sigma_rules', tool_directory, tool_name), exist_ok=True)

    # Remove duplicates
    deduped_tool_data = [dict(t) for t in set(tuple(d.items()) for d in tool_data["data"])]

    # Write out the data to a JSON file inside the tool's directory in sigma_rules
    with open(os.path.join('..', 'sigma_rules', tool_directory, tool_name, f'{tool_name}.json'), 'w') as f:
        json.dump(deduped_tool_data, f, indent=4)
