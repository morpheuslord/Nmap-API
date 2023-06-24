
# Nmap API

Uses python3.10, Debian, python-Nmap, and flask framework to create a Nmap API that can do scans with a good speed online and is easy to deploy.

This is a implementation for our college PCL project which is still under development and constantly updating.


## API Reference

#### Get all items

```text
  GET /api/p1/{auth_key}/{target}
  GET /api/p2/{auth_key}/{target}
  GET /api/p3/{auth_key}/{target}
  GET /api/p4/{auth_key}/{target}
  GET /api/p5/{auth_key}/{target}
```

| Parameter | Type     | Description                |
| :-------- | :------- | :------------------------- |
| `auth_key` | `string` | **Required**. The API auth key gebe |
| `target`| `string`| **Required**. The target Hostname and IP|

#### Get item

```text
  GET /api/p1/
  GET /api/p2/
  GET /api/p3/
  GET /api/p4/
  GET /api/p5/
```

| Parameter | Return data     | Description | Nmap Command |
| :-------- | :------- | :-------------------------------- | :---------|
| `p1`      | `json` | Effective  Scan | `-Pn -sV -T4 -O -F`|
| `p2`      | `json` | Simple  Scan | `-Pn -T4 -A -v`|
| `p3`      | `json` | Low Power  Scan | `-Pn -sS -sU -T4 -A -v`|
| `p4`      | `json` | Partial Intense  Scan | `-Pn -p- -T4 -A -v`|
| `p5`      | `json` | Complete Intense  Scan | `-Pn -sS -sU -T4 -A -PE -PP -PY -g 53 --script=vuln`|


#### Auth and User management

```text
  GET /register/<int:user_id>/<string:password>/<string:unique_key>
```
| Parameter | Type     | Description                |
| :-------- | :------- | :------------------------- |
|`ID`|`Int`|user ID|
|`Passwd`| `String`| User Passwd|
|`Unique_Key`| `String`| User Unique_Key|

## Improvements
Added GPT functionality with chunking module.
The methodology is based on how `Langchain GPT embeddings` operate. Basically, the operation goes like this:

```text
Data -> Chunks_generator ─┐            ┌─> AI_Loop -> Data_Extraction -> Return_Dat
    (GPT3 - 1500 TOKENS)  ├─> Chunk1  ─┤
    (GPT4 - 3500 TOKENS)  ├─> Chunk2  ─┤
                          ├─> Chunk3  ─┤
                          └─> Chunk N ─┘
```
this is how to works:
- **Step 1:**
  - The JSON is done scanning or the text is extracted and converted into a string
- **Step 2:**
  - The long string is converted into individual tokens of words and characters for example `[]{};word` == `'[',']','{','}',';','word'`
- **Step 3:**
  - The long list of tokens is divided into groups of lists according to how many `tokens` we want.
  - for our use case we have a prompt and the data extracted and for simplicity, we went with the chunks of `500 tokens` + the prompt tokens.
- **Step 4:**
  - Step 4 can be achieved in 3 ways `a) Langchain`, `b) OpenAI functions Feature`, `c) The OpenAI API calls`
  - From our tests, the first option `Langchain LLM` did not work as it is not built for such processes
  - The second option `OpenAI functions feature` needed support and more context.
  - The Third was the best as we can provide the rules and output format for it to give an output.
- **Step 5:**
  - The final step is to run the loop and `regex` the output data and return them as an output.
  - The reason for using regex is that `AI is unpredictable` so we need to take measures to keep our data usable.
  - The prompt is used as an output format making sure the AI gives that output no matter what so we can easily regex that output.
 

AI code:
```python
def AI(analyze: str) -> dict[str, any]:
    # Prompt about what the query is all about
    prompt = f"""
        Do a vulnerability analysis report on the following JSON data and
        follow the following rules:
        1) Calculate the criticality score.
        2) Return all the open ports within the open_ports list.
        3) Return all the closed ports within the closed_ports list.
        4) Return all the filtered ports within the filtered_ports list.

        output format: {{
            "open_ports": [],
            "closed_ports": [],
            "filtered_ports": [],
            "criticality_score": ""
            }}

        data = {analize}
    """
    try:
        # A structure for the request
        completion = openai.Completion.create(
            engine=model_engine,
            prompt=prompt,
            max_tokens=1024,
            n=1,
            stop=None,
        )
        response = completion.choices[0].text

        # Assuming extract_ai_output returns a dictionary
        extracted_data = extract_ai_output(response)
    except KeyboardInterrupt:
        print("Bye")
        quit()

    # Store outputs in a dictionary
    ai_output = {
        "open_ports": extracted_data.get("open_ports"),
        "closed_ports": extracted_data.get("closed_ports"),
        "filtered_ports": extracted_data.get("filtered_ports"),
        "criticality_score": extracted_data.get("criticality_score")
    }

    return ai_output
```

The Prompt, Regex and extraction:
```python
    prompt = f"""
        Do a vulnerability analysis report on the following JSON data provided.
        It's the data extracted from my network scanner.
        follow the following rules for analysis:
        1) Calculate the criticality score based on the service or CVE.
        2) Return all the open ports within the open_ports list.
        3) Return all the closed ports within the closed_ports list.
        4) Return all the filtered ports within the filtered_ports list.
        6) Keep the highest possible accuracy.
        7) Do not provide unwanted explanations.
        8) Only provide details in the output_format provided.

        output_format: {{
            "open_ports": [],
            "closed_ports": [],
            "filtered_ports": [],
            "criticality_score": ""
            }}

        data = {analize}
    """
```

The above-mentioned prompt as a distinct output format will return this output no matter the instance. These are the following things needed to be addressed:
- The prompt must be detailed.
- The prompt must explain all sorts of use cases and inputs.
- The prompt must be guided with rules to follow.
- The number of tokens must be monitored and taken care of.

This is the regex for it: 
```python
def extract_ai_output(ai_output: str) -> dict[str, Any]:
    result = {
        "open_ports": [],
        "closed_ports": [],
        "filtered_ports": [],
        "criticality_score": ""
    }

    # Match and extract ports
    open_ports_match = re.search(r'"open_ports": \[([^\]]*)\]', ai_output)
    closed_ports_match = re.search(r'"closed_ports": \[([^\]]*)\]', ai_output)
    filtered_ports_match = re.search(
        r'"filtered_ports": \[([^\]]*)\]', ai_output)

    # If found, convert string of ports to list
    if open_ports_match:
        result["open_ports"] = list(
            map(cast(Callable[[Any], str], int),
                open_ports_match.group(1).split(',')))
    if closed_ports_match:
        result["closed_ports"] = list(
            map(cast(Callable[[Any], str], int),
                closed_ports_match.group(1).split(',')))
    if filtered_ports_match:
        result["filtered_ports"] = list(
            map(cast(Callable[[Any], str], int),
                filtered_ports_match.group(1).split(',')))

    # Match and extract criticality score
    criticality_score_match = re.search(
        r'"criticality_score": "([^"]*)"', ai_output)
    if criticality_score_match:
        result["criticality_score"] = criticality_score_match.group(1)

    return result
```
The regex makes sure all the data is extracted and returned properly within the proper type we wanted. 
This also helps with the data management and removal of unwanted information.

API Key must be mentioned
```python
openai.api_key = '__API__KEY__'
```

### Package
The package is a simple extension for future usage or upgrades it can be installed by running:
```bash
cd package && pip install .
```
The Usage can be implemented like this:
```python
from nmap_api import app

app.openai.api_key = '__API__KEY__'
app.start_api()

```

#### Default User Keys
**Default_Key**: **cff649285012c6caae4d**
