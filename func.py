# utility function to get secret from oci vault
import logging
import io
import oci
import base64

# replace secret_id value below with the ocid of your secret
secret_id = "ocid1.vaultsecret.oc1.uk-london-1.amaaaaaakujrcpiawx73hpzl5ijy4mocmtlrbjyywl3dqherp3mr3kp6p4vq"

# retrieve secret
def get_secret(secret_id):
    # by default this will hit the auth service in the region the instance is running.
    signer = oci.auth.signers.get_resource_principals_signer()
    try
        # get instance principal context
        secret_client = oci.secrets.SecretsClient({}, signer=signer)
        secret_content = secret_client.get_secret_bundle(secret_id).data.secret_bundle_content.encode('utf-8')
        decrypted_secret_content = base64.b64decode(secret_content).decode('utf-8')
    except Exception as ex:
        logging.getLogger().error("get_secret: failed to get secret" + str(ex))
        raise
    return decrypted_secret_content

def handler(ctx, data: io.BytesIO = None):
    logging.getLogger().info("entered get_secret handler")
    ocivault_secret = get_secret(secret_id)
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
