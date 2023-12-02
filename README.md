# Nmap API

Uses python3.10, Debian, python-Nmap, and flask framework to create an Nmap API that can do scans with a good speed online and is easy to deploy.

This is an implementation for our college PCL project which is still under development and constantly updating.

## API Reference

#### Get all items

```
  GET /api/p1/{auth_key}/{target}
  GET /api/p2/{auth_key}/{target}
  GET /api/p3/{auth_key}/{target}
  GET /api/p4/{auth_key}/{target}
  GET /api/p5/{auth_key}/{target}
```

| Parameter  | Type     | Description                              |
| :--------- | :------- | :--------------------------------------- |
| `auth_key` | `string` | **Required**. The API auth key gebe      |
| `target`   | `string` | **Required**. The target Hostname and IP |

#### Get item

```
  GET /api/p1/
  GET /api/p2/
  GET /api/p3/
  GET /api/p4/
  GET /api/p5/
  GET /api/p6/
  GET /api/p7/
  GET /api/p8/
  GET /api/p9/
  GET /api/p10/
  GET /api/p11/
  GET /api/p12/
  GET /api/p13/
```

| Parameter | Return data | Description                                          | Nmap Command                                          |
| :-------- | :---------- | :--------------------------------------------------- | :---------------------------------------------------- |
| `p1`      | `json`      | Effective Scan                                       | `-Pn -sV -T4 -O -F`                                   |
| `p2`      | `json`      | Simple Scan                                          | `-Pn -T4 -A -v`                                       |
| `p3`      | `json`      | Low Power Scan                                       | `-Pn -sS -sU -T4 -A -v`                               |
| `p4`      | `json`      | Partial Intense Scan                                 | `-Pn -p- -T4 -A -v`                                   |
| `p5`      | `json`      | Complete Intense Scan                                | `-Pn -sS -sU -T4 -A -PE -PP  -PY -g 53 --script=vuln` |
| `p6`      | `json`      | Comprehensive Service Version Detection              | `-Pn -sV -p- -A`                                      |
| `p7`      | `json`      | Aggressive Scan with OS Detection                    | `-Pn -sS -sV -O -T4 -A`                               |
| `p8`      | `json`      | Script Scan for Common Vulnerabilities               | `-Pn -sC`                                             |
| `p9`      | `json`      | Intense Scan, All TCP Ports                          | `-Pn -p 1-65535 -T4 -A -v`                            |
| `p10`     | `json`      | UDP Scan                                             | `-Pn -sU -T4`                                         |
| `p11`     | `json`      | Service and Version Detection for Top Ports          | `-Pn -sV --top-ports 100`                             |
| `p12`     | `json`      | Aggressive Scan with NSE Scripts for Vulnerabilities | `-Pn -sS -sV -T4 --script=default,discovery,vuln`     |
| `p13`     | `json`      | Fast Scan for Common Ports                           | `-Pn -F`                                              |

#### Auth and User management

```
  GET /register/<int:user_id>/<string:password>
```

| Parameter | Type     | Description |
| :-------- | :------- | :---------- |
| `ID`      | `Int`    | user ID     |
| `Passwd`  | `String` | User Passwd |

## Improvements

Added GPT functionality with chunking module.
The methodology is based on how `Langchain GPT embeddings` operate. Basically the operation goes like this:

```text
Data -> Chunks_generator ─┐            ┌─> AI_Loop -> Data_Extraction -> Return_Data
                          ├─> Chunk1  ─┤
                          ├─> Chunk2  ─┤
                          ├─> Chunk3  ─┤
                          └─> Chunk N ─┘
```

AI code:

```python
def AI(analize: str) -> dict[str, any]:
    prompt = f"""
        Do a NMAP scan analysis on the provided NMAP scan information
        The NMAP output must return in a JSON format accorging to the provided
        output format. The data must be accurate in regards towards a pentest report.
        The data must follow the following rules:
        1) The NMAP scans must be done from a pentester point of view
        2) The final output must be minimal according to the format given.
        3) The final output must be kept to a minimal.
        4) If a value not found in the scan just mention an empty string.
        5) Analyze everything even the smallest of data.
        6) Completely analyze the data provided and give a confirm answer using the output format.

        The output format:
        {{
            "critical score": [""],
            "os information": [""],
            "open ports": [""],
            "open services": [""],
            "vulnerable service": [""],
            "found cve": [""]
        }}

        NMAP Data to be analyzed: {analize}
    """
    messages = [{"content": prompt, "role": "assistant"}]
    response = openai.ChatCompletion.create(
        model=model_engine,
        messages=messages,
        max_tokens=2500,
        n=1,
        stop=None,
    )
    response = response['choices'][0]['message']['content']
    ai_output = {
        "markdown": response
    }

    return ai_output
```

**Default_Key**: **e43d4**
