import json


def save_to_json_file(json_data, filename, path="./files/"):
    json_string = json.dumps(json_data, indent=4)
    __write_to_file__(json_string, filename, path)


def save_json_string(string, filename, path="./files/"):
    __write_to_file__(string, filename, path)


def print_obj_in_file(original_obj, filename, path="./files"):
    json_array = [json.loads(p.serialize(indent=4)) for p in original_obj]
    final_json = json.dumps({"objects": json_array}, indent=4)
    save_json_string(final_json, filename, path)


def __write_to_file__(file_content, filename, path):
    with open(f"{path}{filename}", "w") as outfile:
        outfile.write(file_content)
