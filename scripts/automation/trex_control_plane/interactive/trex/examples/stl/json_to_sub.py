from types import SimpleNamespace
import json

class Subscriber(object):
    def __init__(self, id, ip, username, password, mac):
        self.id = id
        self.ip = ip
        self.username = username
        self.password = password
        self.mac = mac


def object_hook(obj):
    JsonParser.obj_list.append(Subscriber(
        obj['id'],
        obj['ip'],
        obj['username'],
        obj['password'],
        obj['mac'],
        ))

class JsonParser:
    def __init__(self, filepath):
        self.raw_data = open(filepath, 'r')
    
    obj_list = []
    
    def deserialize(self):
        data_str = self.raw_data.read()
        json.loads(data_str, object_hook=object_hook)
        return JsonParser.obj_list
