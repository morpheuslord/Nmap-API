import nmap
import sqlite3
import re
import openai
import hashlib
import requests
import jsonify
import docker
import atexit
import psutil
import os
from dotenv import load_dotenv
from contextlib import contextmanager
from flask import Flask, render_template
from flask_restful import Api, Resource

load_dotenv()
openai.api_key = os.getenv("OPENAI_API_KEY")
IMAGE_NAME = os.getenv("IMAGE_NAME")
BASE_PORT = os.getenv("BASE_PORT")
NUM_INSTANCES = os.getenv("NUM_INSTANCES")
model_engine = "gpt-3.5-turbo-0613"

app = Flask(__name__)
api = Api(app)

nm = nmap.PortScanner()
started_containers = []
last_used_instance = 0
client = docker.from_env()


@app.route('/', methods=['GET'])
def home():
    return render_template("index.html")


@app.route('/doc', methods=['GET'])
def doc():
    return render_template("doc.html")


@contextmanager
def get_db_connection():
    db_file = 'auth_keys.db'
    conn = sqlite3.connect(db_file)
    try:
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS auth_keys (
                          user_id INT PRIMARY KEY NOT NULL,
                          auth_key TEXT NOT NULL,
                          unique_key TEXT NOT NULL);''')
        conn.commit()

        yield conn
    finally:
        conn.close()


def sanitize(input_string: str) -> str:
    patterns_to_remove = [
        r";",
        r"'",
        r'"',
        r"\b(SELECT|UPDATE|DELETE|INSERT|DROP|ALTER|CREATE|TABLE|DATABASE)\b",
        r"--",
        r"\b(OR|AND)\b.{0,20}?=",
        r"%"
    ]

    sanitized_string = input_string
    for pattern in patterns_to_remove:
        sanitized_string = re.sub(
            pattern, "", sanitized_string, flags=re.IGNORECASE)

    return sanitized_string


@app.route('/register/<int:user_id>/<string:password>/<string:unique_key>')
def store_auth_key(user_id, password, unique_key):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        hash = hashlib.sha256()
        hash.update(str(user_id).encode('utf-8'))
        hash.update(password.encode('utf-8'))
        hash.update(unique_key.encode('utf-8'))
        auth_key = hash.hexdigest()[:20]
        cursor.execute("SELECT 1 FROM auth_keys WHERE user_id = ?", (user_id,))
        if cursor.fetchone():
            return jsonify({"error": "User ID already exists"})
        cursor.execute(
            "INSERT INTO auth_keys (user_id, auth_key, unique_key) VALUES (?, ?, ?)",
            (user_id, auth_key, unique_key)
        )
        conn.commit()

    return auth_key


def authenticate(auth_key):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT 1 FROM auth_keys WHERE auth_key = ?", (
                sanitize(auth_key),)
        )
        return cursor.fetchone() is not None


def cleanup_containers():
    client = docker.from_env()
    for container_id in started_containers:
        try:
            container = client.containers.get(container_id)
            container.stop()
            container.remove()
            print(f"Stopped and removed container {container_id}")
        except Exception as e:
            print(f"Error stopping/removing container {container_id}: {e}")


def deploy_docker_instances(image_name, start_port, num_instances):
    client = docker.from_env()
    for i in range(num_instances):
        host_port = start_port + i
        container_port = '5000/tcp'
        port_bindings = {container_port: host_port}
        container = client.containers.run(
            image_name, detach=True, ports=port_bindings)
        print(
            f"Started container {container.short_id} on host port {host_port} mapped to container port 5000")
        started_containers.append(container.id)
    atexit.register(cleanup_containers)


def get_total_resource_usage():
    total_memory_usage = 0
    total_cpu_usage = 0

    for container in client.containers.list():
        stats = container.stats(stream=False)
        memory_usage = stats['memory_stats']['usage']
        total_memory_usage += memory_usage

        cpu_delta = stats['cpu_stats']['cpu_usage']['total_usage'] - \
            stats['precpu_stats']['cpu_usage']['total_usage']
        system_delta = stats['cpu_stats']['system_cpu_usage'] - \
            stats['precpu_stats']['system_cpu_usage']
        if system_delta > 0.0 and cpu_delta > 0.0:
            cpu_usage = (cpu_delta / system_delta) * \
                len(stats['cpu_stats']['cpu_usage']['percpu_usage'])
            total_cpu_usage += cpu_usage

    return total_memory_usage, total_cpu_usage


@app.route('/checkup')
def monitor_and_manage_containers():
    CLEAN_NEEDED = "NO"
    total_memory_usage, total_cpu_usage = get_total_resource_usage()

    total_available_memory = psutil.virtual_memory().total
    total_available_cpu = psutil.cpu_count()

    memory_usage_percent = (total_memory_usage / total_available_memory) * 100
    cpu_usage_percent = (total_cpu_usage / total_available_cpu) * 100
    print("Total Available CPU: {total_available_cpu}")
    print("Total Available RAM: {total_available_memory}")
    print("Total Usage CPU: {total_cpu_usage}")
    print("Total Usage RAM: {total_memory_usage}")
    print("Total Usage CPU %: {cpu_usage_percent}")
    print("Total Usage RAM %: {memory_usage_percent}")

    print(
        f"Memory Usage: {memory_usage_percent}%, CPU Usage: {cpu_usage_percent}%")

    if memory_usage_percent > 50 or cpu_usage_percent > 50:
        cleanup_containers()
        deploy_docker_instances(IMAGE_NAME, BASE_PORT, NUM_INSTANCES)
        CLEAN_NEEDED = "YES"
    return {
        "Total Available CPU": f"{total_available_cpu}",
        "Total Available RAM": f"{total_available_memory}",
        "Total Usage CPU": f"{total_cpu_usage}",
        "Total Usage RAM": f"{total_memory_usage}",
        "Total Usage CPU %": f"{cpu_usage_percent}",
        "Total Usage RAM %": f"{memory_usage_percent}",
        "CLEANUP NEEDED": f"{CLEAN_NEEDED}",
    }


def profile(auth, url, profile):
    global last_used_instance

    if not authenticate(auth):
        return {"error": "Authentication failed"}
    base_url = "http://127.0.0.1"
    start_port = 5001
    num_instances = 10
    selected_instance = (last_used_instance + 1) % num_instances
    last_used_instance = selected_instance
    port = start_port + selected_instance
    full_url = f"{base_url}:{port}/api/{profile}/{url}"

    try:
        response = requests.get(full_url)
        if response.status_code == 200:
            data = response.json()
            d = str(data.get("scan", {}))
            return AI(d)
        else:
            print(f"Error from server: {response.status_code}")
            return {
                "error": f"Server responded with status code {response.status_code}"
            }
    except requests.RequestException as e:
        print(f"Request failed: {e}")
        return {"error": "Request failed"}


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


class ScanAPI(Resource):
    def get(self, auth, url, scan_type):
        return profile(
            auth=auth,
            profile=scan_type,
            url=url
        )


api.add_resource(ScanAPI, "/api/<string:scan_type>/<string:auth>/<string:url>")
