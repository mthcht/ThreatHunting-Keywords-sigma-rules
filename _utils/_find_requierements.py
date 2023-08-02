import os
import ast

def find_imports(filename):
    with open(filename, 'r') as file:
        tree = ast.parse(file.read())
    return [node.names[0].name for node in ast.walk(tree) if isinstance(node, ast.Import)]

# get the scripts directory
scripts_directory = os.getcwd()

modules = set()
for script in os.listdir(scripts_directory):
    if script.endswith(".py"):
        modules.update(find_imports(os.path.join(scripts_directory, script)))

with open("requirements.txt", "w") as req_file:
    for module in modules:
        req_file.write(module + "\n")
