import requests
import json
from rich.markdown import Markdown
from rich.console import Console
from rich import print

console = Console()

username = "one"
uID = "2434"
ukey = "cfffbjewkb"

register = requests.get(f"http://127.0.0.1/register/{uID}/{username}/{ukey}")
key = register.text
print("Key Generated:")
print(key)

url = f"http://127.0.0.1/api/p1/{key}/172.67.147.95"
print(url)
response = requests.get(url)
data = response.text
data_processed = json.loads(data)
t = f"""
### API Registration Details
``
`Username:` = {username}

`Unique Key:` = {ukey}

`ID:` = {uID}

`KEY` = {key}

### AI OUTPUT
`IP` = 127.0.0.1

`Profile` = P1

```json
{data_processed["markdown"]}
```
"""
out = Markdown(t)
console.print(out)
