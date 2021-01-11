import json
import base64
import logging
import os
import sys
import requests
import time
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from kubernetes import config, client
from openshift.dynamic import DynamicClient

# Disable InsecureRequestWarning warnings while connecting to OpenShift API
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


# Check if code is running in OpenShift
if "KUBERNETES_SERVICE_HOST" in os.environ and "KUBERNETES_SERVICE_PORT" in os.environ:
    config.load_incluster_config()
else:
    config.load_kube_config()

# Create a client config
k8s_config = client.Configuration()

# Create K8 and dynamic client instances
# k8s_client = config.new_client_from_config()
try:
    k8s_client = client.api_client.ApiClient(configuration=k8s_config)
    dyn_client = DynamicClient(k8s_client)
except Exception as error:
    print("An exception occurred: {}".format(error))
    sys.exit(1)

# Function to read the environment parameters and create config dict
def getConfig():
    config = {}
    try:
        config["MOUNT_PATH_TO_READ_SECRETS"] = os.environ["MOUNT_PATH_TO_READ_SECRETS"]
        config["POD_NAMESPACE"] = os.environ["POD_NAMESPACE"]
        config["OCP_IMAGE_PULL_SECRETS_REFRESH_SECONDS"] = os.environ[
            "OCP_IMAGE_PULL_SECRETS_REFRESH_SECONDS"
        ]
    except KeyError as key:
        log.error("Environment Variable {} not found".format(key))
        sys.exit(1)

    if not config["MOUNT_PATH_TO_READ_SECRETS"].endswith("/"):
        config["MOUNT_PATH_TO_READ_SECRETS"] = (
            config["MOUNT_PATH_TO_READ_SECRETS"] + "/"
        )

    return config


# Function to read image pull secret files from MOUNT_PATH_TO_READ_SECRETS
def readSecretsFile(file):

    try:
        with open(file) as f:
            return json.load(f)
    except OSError:
        log.error("Could not open/read file: {}".format(file))
        sys.exit(1)


# Function to create payload and encrypt it
def createPayload(data):

    cred_payload = {
        "auths": {
            data["data"]["registry-server"]: {
                "Username": data["data"]["username"],
                "Password": data["data"]["password"],
            }
        }
    }

    cred_encrypted = {
        ".dockerconfigjson": base64.b64encode(
            json.dumps(cred_payload).encode()
        ).decode()
    }

    return cred_encrypted


# Functiom to get list of secret file written by vault side car to mount point: MOUNT_PATH_TO_READ_SECRETS
def getFilelist(dir_path):

    file_list = []
    for r, d, f in os.walk(dir_path):
        for file in f:
            file_list.append(os.path.join(r, file))

    return file_list


# Function to create image pull secret
def createImagePullSecret(dockerConfigString, registerServer):

    try:
        v1_sec = dyn_client.resources.get(api_version="v1", kind="Secret")
    except Exception as error:
        log.error("An exception occurred: {}".format(error))
        sys.exit(1)

    imagePullSecretName = registerServer + "-imagepullsecret"

    body = {
        "kind": "Secret",
        "apiVersion": "v1",
        "metadata": {"name": imagePullSecretName},
        "type": "kubernetes.io/dockerconfigjson",
        "data": dockerConfigString,
    }

    log.debug("{} image pull secret json definition".format(imagePullSecretName))
    log.debug(body)

    secrets_list = []

    for secret in v1_sec.get(namespace=config["POD_NAMESPACE"]).items:
        secrets_list.append(secret.metadata.name)

    log.debug("List of Secrets in namespace: {}".format(config["POD_NAMESPACE"]))
    log.debug(secrets_list)

    if imagePullSecretName in secrets_list:
        log.info("{} image pull secret exists".format(imagePullSecretName))
        log.info(
            "Check if the image pull secret: {} is modified in vault".format(
                imagePullSecretName
            )
        )
        log.info(
            "Get the image pull secret: {} from OpenShift Container Platform".format(
                imagePullSecretName
            )
        )

        imagePullSecretFromVault = dockerConfigString[".dockerconfigjson"]
        imagePullSecretFromOCP = v1_sec.get(
            namespace=config["POD_NAMESPACE"], name=imagePullSecretName
        )
        imagePullSecretFromOCP = imagePullSecretFromOCP.data[".dockerconfigjson"]

        log.debug("Image pull secret from Vault: {}".format(imagePullSecretFromVault))
        log.debug(
            "Image pull secret from OpenShift Container Platform: {}".format(
                imagePullSecretFromOCP
            )
        )

        # Check if the image pull secret are same. if same, don't update the ocp secret else update
        if imagePullSecretFromVault == imagePullSecretFromOCP:
            log.info(
                "{} image pull secret from Vault and OpenShift Container Platform are same, so not updating".format(
                    imagePullSecretName
                )
            )
        else:
            log.info(
                "{} image pull secret from Vault and OpenShift Container Platform are not same, so updating".format(
                    imagePullSecretName
                )
            )
            # Update the secret if secrets from vault and openshift are different
            try:
                v1_sec.patch(body=body, namespace=config["POD_NAMESPACE"])
            except Exception as error:
                log.error("An exception occurred: {}".format(error))
                sys.exit(1)

            log.info("{} image pull secret updated".format(imagePullSecretName))
    else:
        log.info(
            "{} image pull secret does not exists, so creating".format(
                imagePullSecretName
            )
        )
        try:
            v1_sec.create(body=body, namespace=config["POD_NAMESPACE"])
        except Exception as error:
            log.error("An exception occurred: {}".format(error))
            sys.exit(1)

        log.info("{} image pull secret created".format(imagePullSecretName))


if __name__ == "__main__":

    # Log settings
    log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        stream=sys.stdout, format="[%(asctime)s] [%(levelname)s] - %(message)s"
    )
    log = logging.getLogger()
    level = logging.getLevelName(log_level)
    log.setLevel(log_level)

    # Print effective log level
    log.info("Log Level: {}".format(logging.getLevelName(log.getEffectiveLevel())))

    log.info("Loading configuration from environment variables")

    # Load configurations from environment
    config = getConfig()
    log.debug("Configuration from environment variables:")

    # Print configuration values if debug mode
    for key in config:
        log.debug("{}: {}".format(key, config[key]))

    while True:

        # Get list if files to read from MOUNT_PATH_TO_READ_SECRETS path
        file_list = getFilelist(config["MOUNT_PATH_TO_READ_SECRETS"])

        log.debug(
            "List of secret files available from mount:{} are {}".format(
                config["MOUNT_PATH_TO_READ_SECRETS"], file_list
            )
        )

        # Loop through each image pull secret file to create corresponding image pull secret in namespace
        for file in file_list:
            # Read secrets file from MOUNT_PATH_TO_READ_SECRETS
            log.info("Read secrets from file: {}".format(file))
            data = readSecretsFile(file)

            log.info("Create image pull secret payload")
            docker_cfg_string = createPayload(data)

            log.info("Create image pull secret")
            createImagePullSecret(docker_cfg_string, data["data"]["registry-server"])

        log.info(
            "Waiting for {} seconds before connecting to refreshing secrets".format(
                config["OCP_IMAGE_PULL_SECRETS_REFRESH_SECONDS"]
            )
        )
        time.sleep(int(config["OCP_IMAGE_PULL_SECRETS_REFRESH_SECONDS"]))
