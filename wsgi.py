# need to change the prod to work well
import os
from app import app, deploy_docker_instances
from dotenv import load_dotenv

load_dotenv()
IMAGE_NAME = os.getenv("IMAGE_NAME")
BASE_PORT = os.getenv("BASE_PORT")
NUM_INSTANCES = os.getenv("NUM_INSTANCES")

if __name__ == "__main__":
    deploy_docker_instances(IMAGE_NAME, BASE_PORT, NUM_INSTANCES)
    app.run()
