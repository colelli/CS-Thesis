import requests
import yaml
import ToFileUtils as tfu
import codecs

DEFAULT_ATLAS_FILE_PATH = "../files/ATLAS.yaml"


def get_atlas_yaml(branch: str = "main"):
    atlas = requests.get(f"https://raw.githubusercontent.com/mitre-atlas/atlas-data/{branch}/dist/ATLAS.yaml").text
    tfu.save_string_to_file(atlas, "ATLAS.yaml")


def parse_yaml():
    with open(DEFAULT_ATLAS_FILE_PATH) as yaml_file:
        # Parse YAML
        data = yaml.safe_load(yaml_file)
        first_matrix = data['matrices'][0]
        tactics = first_matrix['tactics']
        print(tactics)


parse_yaml()
