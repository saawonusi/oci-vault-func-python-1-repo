# utility function to get secrets from oci vault
import logging
import io
import oci
import base64

# Replace secret_id value below with the ocid of your secret
secret_id = "ocid1.vaultsecret.oc1.uk-london-1.amaaaaaakujrcpiawx73hpzl5ijy4mocmtlrbjyywl3dqherp3mr3kp6p4vq"

# By default this will hit the auth service in the region the instance is running.
signer = oci.auth.signers.get_resource_principals_signer()

# In the base case, configuration does not need to be provided as the region and tenancy are obtained from the InstancePrincipalsSecurityTokenSigner
identity_client = oci.identity.IdentityClient(config={}, signer=signer)

# Get instance principal context
secret_client = oci.secrets.SecretsClient(config={}, signer=signer)

# Retrieve secret
def read_secret_value(secret_client, secret_id):
    response = secret_client.get_secret_bundle(secret_id)
    logging.getLogger().info("entered read_secret_value handler")
    try:
        base64_Secret_content = response.data.secret_bundle_content.content
        base64_secret_bytes = base64_Secret_content.encode('utf-8')
        base64_message_bytes = base64.b64decode(base64_secret_bytes)
        secret_content = base64_message_bytes.decode('utf-8')
    except Exception as ex:
        logging.getLogger().error("read_secret_value: Failed to get Secret" + str(ex))
        raise
    return secret_content

# Print secret
secret_contents = read_secret_value(secret_client, secret_id)
print(format(secret_contents))


def handler(ctx, data: io.BytesIO = None):
    ocivault_secret = read_secret_value(secret_client, secret_id)
    print(format(ocivault_secret))

"""
import io
import json
import logging

from fdk import response


def handler(ctx, data: io.BytesIO = None):
    name = "World"
    try:
        body = json.loads(data.getvalue())
        name = body.get("name")
    except (Exception, ValueError) as ex:
        logging.getLogger().info('error parsing json payload: ' + str(ex))

    logging.getLogger().info("Inside Python Hello World function")
    return response.Response(
        ctx, response_data=json.dumps(
            {"message": "Hello {0}".format(name)}),
        headers={"Content-Type": "application/json"}
    )
"""
