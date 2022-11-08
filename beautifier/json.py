from . import json


def parse(txt):
    return json.dumps(json.loads(txt), indent=2, sort_keys=True)
