# utility function to get secret from oci vault
import logging
import io
import oci
import base64

secret_name = "ipaas-client-secret-2"
# replace vault_id value below with the ocid of your vault
vault_id = "ocid1.vault.oc1.uk-london-1.d5sitxohaaa6k.abwgiljtbl5pupmmj3haubob3hb475qozryypozwtr7ukjw4wa46qvcmocya"

# retrieve secret
def get_secret(secret_name,vault_id):
    # by default this will hit the auth service in the region the instance is running.
    signer = oci.auth.signers.get_resource_principals_signer()
    # decrypted_secret_content = ""
    try:
        # get instance principal context
        secret_client = oci.secrets.SecretsClient({}, signer=signer)
        secret_content = secret_client.get_secret_bundle_by_name(secret_name,vault_id).data.secret_bundle_content.content.encode('utf-8')
        # decode and decrypt the secret_content
        decrypted_secret_content = base64.b64decode(secret_content).decode('utf-8')
    except Exception as ex:
        logging.getLogger().error("get_secret: failed to get secret" + str(ex))
        raise
    return decrypted_secret_content

def handler(ctx, data: io.BytesIO = None):
    logging.getLogger().info("entered get_secret handler")
    ocivault_secret = get_secret(secret_name,vault_id)
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
