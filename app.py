import hashlib
import json
import os
import re
import sqlite3
from typing import Any

import nmap
import openai

from flask import Flask
from flask import request
from flask import render_template
from flask_restful import Api
from flask_restful import Resource

openai.api_key = '__API__KEY__'
model_engine = "text-davinci-003"

app = Flask(__name__)
api = Api(app)

nm = nmap.PortScanner()


# Index and Docx page
@app.route('/', methods=['GET'])
def home() -> Any:
    return render_template("index.html")


@app.route('/doc', methods=['GET'])
def doc() -> Any:
    return render_template("doc.html")


@app.route('/register', methods=['POST'])
def store_auth_key():
    data = request.get_json()

    user_id = data.get('user_id')
    uname = data.get('username')
    passwd = data.get('password')
    u_key = data.get('unique_key')
    role = data.get('role')
    priority = data.get('priority')

    sanitized_username = user_id
    sanitized_passwd = passwd
    sanitized_key = u_key

    hash = hashlib.sha256()
    hash.update(str(sanitized_username).encode('utf-8'))
    hash.update(sanitized_passwd.encode('utf-8'))
    hash.update(sanitized_key.encode('utf-8'))

    auth_key = hash.hexdigest()[:20]

    user_db_file = 'users.db'
    conn_user = sqlite3.connect(user_db_file)
    cursor_user = conn_user.cursor()

    cursor_user.execute('''CREATE TABLE IF NOT EXISTS users
                        (user_id INT PRIMARY KEY NOT NULL,
                        username TEXT NOT NULL,
                        role TEXT NOT NULL,
                        priority TEXT NOT NULL);''')

    query_user = (
        "INSERT INTO users "
        "(user_id, username, role, priority) "
        "VALUES (?, ?, ?, ?)"
    )
    cursor_user.execute(
        query_user,
        (sanitized_username, uname, role, priority)
    )

    conn_user.commit()
    conn_user.close()

    db_file = 'auth_keys.db'
    need_create_table = not os.path.exists(db_file)
    conn_auth = sqlite3.connect(db_file)
    cursor_auth = conn_auth.cursor()

    if need_create_table:
        cursor_auth.execute('''CREATE TABLE IF NOT EXISTS auth_keys
                            (user_id INT PRIMARY KEY NOT NULL,
                            auth_key TEXT NOT NULL,
                            unique_key TEXT NOT NULL,
                            role TEXT NOT NULL,
                            priority TEXT NOT NULL);''')

    query_auth = (
        "INSERT INTO auth_keys "
        "(user_id, auth_key, unique_key, role, priority) "
        "VALUES (?, ?, ?, ?, ?)"
    )
    cursor_auth.execute(
        query_auth,
        (sanitized_username, auth_key, sanitized_key, priority, priority)
    )

    conn_auth.commit()
    conn_auth.close()

    return auth_key


@app.route('/getuser/<string:admin_key>')
def get_all_users(admin_key: str) -> str:
    conn_auth = sqlite3.connect('auth_keys.db')
    cursor_auth = conn_auth.cursor()
    sanitized_key = sanitize(admin_key)
    query = f"SELECT role FROM auth_keys WHERE auth_key = '{sanitized_key}'"
    cursor_auth.execute(
        query
    )
    auth_row = cursor_auth.fetchone()
    if auth_row:
        conn_users = sqlite3.connect('users.db')
        cursor_users = conn_users.cursor()

        cursor_users.execute("SELECT * FROM users")
        rows = cursor_users.fetchall()

        users = []
        for row in rows:
            user = {
                "user_id": row[0],
                "username": row[1],
                "role": row[2],
                "priority": row[3]
            }
            users.append(user)

        conn_users.close()
        conn_auth.close()
        return json.dumps(users)

    conn_auth.close()
    return json.dumps({"error": "Unauthorized access. Admin key required."})


# Admin : 60e709884276ce6096d1
@app.route('/rmuser/<int:id>/<string:username>/<string:key>')
def remove_user(id: int, username: str, key: str) -> Any:
    conn_auth = sqlite3.connect('auth_keys.db')
    cursor_auth = conn_auth.cursor()

    cursor_auth.execute(
        "SELECT user_id, role FROM auth_keys WHERE auth_key = ?", (key,))
    auth_row = cursor_auth.fetchone()

    if auth_row:
        role = auth_row[1]
        if role == "admin":
            conn_auth.close()
            pass
    else:
        return {"error": "Unauthorized access. Admin key required."}

    conn_users = sqlite3.connect('users.db')
    cursor_users = conn_users.cursor()
    conn_auth = sqlite3.connect('auth_keys.db')
    cursor_auth = conn_auth.cursor()

    cursor_users.execute(
        "DELETE FROM users WHERE user_id = ? AND username = ?",
        (id, username)
    )

    cursor_auth.execute(
        "DELETE FROM auth_keys WHERE user_id = ?",
        (id,)
    )

    conn_users.commit()
    conn_auth.commit()
    conn_users.close()
    conn_auth.close()

    removed_user = {
        "username": username,
        "user_id": id
    }

    return removed_user


def to_int(s: str) -> int:
    return int(s)


def sanitize(input_string: str) -> str:
    if not re.match("^[a-zA-Z0-9]*$", input_string):
        raise ValueError("Invalid characters in string")
    else:
        return input_string


def chunk_output(scan_output: dict,
                 max_token_size: int) -> list[dict[str, Any]]:
    output_chunks = []
    current_chunk = {}
    current_token_count = 0

    # Convert JSON to AI usable chunks
    for ip, scan_data in scan_output.items():
        new_data_token_count = len(json.dumps({ip: scan_data}).split())

        if current_token_count + new_data_token_count <= max_token_size:
            current_chunk[ip] = scan_data
            current_token_count += new_data_token_count
        else:
            output_chunks.append(current_chunk)
            current_chunk = {ip: scan_data}
            current_token_count = new_data_token_count
    # The Chunks list that is returned
    if current_chunk:
        output_chunks.append(current_chunk)

    return output_chunks


def AI(analize: str) -> dict[str, Any]:
    # Prompt about what the query is all about
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

        NMAP Data to be analyzed: {data}
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
        response = completion.choices[0]['text']

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


def authenticate(auth_key: str) -> bool:
    conn_auth = sqlite3.connect('auth_keys.db')
    cursor_auth = conn_auth.cursor()
    conn_users = sqlite3.connect('users.db')
    cursor_users = conn_users.cursor()

    key = sanitize(auth_key)

    # Check if the given auth_key exists in the auth_keys table
    cursor_auth.execute(
        "SELECT user_id FROM auth_keys WHERE auth_key = ?", (key,))
    auth_row = cursor_auth.fetchone()

    if auth_row:
        user_id = auth_row[0]

        # Check if the user ID exists in the users table
        cursor_users.execute(
            "SELECT user_id FROM users WHERE user_id = ?", (user_id,))
        user_row = cursor_users.fetchone()

        if user_row:
            # If the user IDs match, return True
            conn_auth.close()
            conn_users.close()
            return True

    conn_auth.close()
    conn_users.close()

    # Return an error message if the keys provided are incorrect
    return False


def extract_ai_output(ai_output: str) -> dict[str, Any]:
    result: dict[str, Any] = {
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
        open_ports_str = open_ports_match.group(1)
        try:
            if open_ports_str:
                result["open_ports"] = list(
                    map(int, open_ports_str.split(',')))
        except ValueError:
            pass
    if closed_ports_match:
        closed_ports_str = closed_ports_match.group(1)
        try:
            if closed_ports_str:
                result["closed_ports"] = list(
                    map(int, closed_ports_str.split(',')))
        except ValueError:
            pass
    if filtered_ports_match:
        filtered_ports_str = filtered_ports_match.group(1)
        try:
            if filtered_ports_str:
                result["filtered_ports"] = list(
                    map(int, filtered_ports_str.split(',')))
        except ValueError:
            pass
    # Match and extract criticality score
    criticality_score_match = re.search(
        r'"criticality_score": "([^"]*)"', ai_output)
    if criticality_score_match:
        result["criticality_score"] = criticality_score_match.group(1)

    return result


def profile(auth: str, url: str, argument: str) -> dict[str, Any]:
    ip = url
    # Nmap Execution command
    usernamecheck = authenticate(auth)
    if usernamecheck is False:
        return {"error": "passwd or username error"}
    else:
        nm.scan('{}'.format(ip), arguments='{}'.format(argument))
        scan_data = nm.analyse_nmap_xml_scan()
        analyze = scan_data["scan"]
        converted_data = str(analyze)
        data = AI(converted_data)
        return json.dumps(data)
        # return analyze


# Effective  Scan
class p1(Resource):
    def get(self, auth, url):
        argument = '-Pn -sV -T4 -O -F'
        scan = profile(auth, url, argument)
        return scan


# Simple Scan
class p2(Resource):
    def get(self, auth, url):
        argument = '-Pn -T4 -A -v'
        scan = profile(auth, url, argument)
        return scan


# Low Power Scan
class p3(Resource):
    def get(self, auth, url):
        argument = '-Pn -sS -sU -T4 -A -v'
        scan = profile(auth, url, argument)
        return scan


# partial Intense Scan
class p4(Resource):
    def get(self, auth, url):
        argument = '-Pn -p- -T4 -A -v'
        scan = profile(auth, url, argument)
        return scan


# Complete Intense scan
class p5(Resource):
    def get(self, auth, url):
        argument = '-Pn -sS -sU -T4 -A -PE -PP -PY -g 53 --script=vuln'
        scan = profile(auth, url, argument)
        return scan


api.add_resource(
    p1, "/api/p1/<string:auth>/<string:url>")
api.add_resource(
    p2, "/api/p2/<string:auth>/<string:url>")
api.add_resource(
    p3, "/api/p3/<string:auth>/<string:url>")
api.add_resource(
    p4, "/api/p4/<string:auth>/<string:url>")
api.add_resource(
    p5, "/api/p5/<string:auth>/<string:url>")
