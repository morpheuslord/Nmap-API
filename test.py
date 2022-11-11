import http.client
import json
import dicttoxml

conn = http.client.HTTPConnection("127.0.0.1:5010")

payload = ""

conn.request("GET", "/api/p1/admin:passwd/127.0.0.1", payload)

res = conn.getresponse()
data = res.read()
final = json.loads(data)
print(final)