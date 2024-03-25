import requests
import yaml
import ToFileUtils as tfu

DEFAULT_ATLAS_FILE_PATH = "../files/ATLAS.yaml"


def get_atlas_yaml(branch: str = "main"):
    atlas = requests.get(f"https://raw.githubusercontent.com/mitre-atlas/atlas-data/{branch}/dist/ATLAS.yaml").text
    tfu.save_string_to_file(atlas, "ATLAS.yaml")


def parse_yaml():
    with open(DEFAULT_ATLAS_FILE_PATH) as yaml_file:
        # Parse YAML
        data = yaml.safe_load(yaml_file)
        tfu.save_to_json_file(data, "atlas-to-json")
        for i in range(len(data['matrices'])):
            matrix = data['matrices'][i]
            case_studies = data['case-studies'][i]
            tfu.save_to_json_file(matrix, f"matrices_{i}")
            tfu.save_to_json_file(case_studies, f"case_studies_{i}")
            tfu.save_to_json_file(matrix['tactics'], f"tactics_{i}")
            tfu.save_to_json_file(matrix['techniques'], f"techniques_{i}")
            tfu.save_to_json_file(matrix['mitigations'], f"mitigations_{i}")
            """
            for j in range(len(matrix)):
                tfu.save_to_json_file(matrix['tactics'][j], f"tactics_{i}_{j}")
                tfu.save_to_json_file(matrix['techniques'][j], f"techniques_{i}_{j}")
                tfu.save_to_json_file(matrix['mitigations'][j], f"mitigations_{i}_{j}")
            """


parse_yaml()
