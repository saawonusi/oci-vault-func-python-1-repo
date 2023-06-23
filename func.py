# utility function to get secret from oci vault
import io
import json
import logging
import base64
import sys
import oci
from oci.key_management.models import DecryptDataDetails
from fdk import response
# if function fails with no module 'oci', add oci to the requirements.txt file to force docker to  add it

def handler(ctx, data: io.BytesIO = None):
    apitoken_secret = ""
    try:

        #passing the signer uses what would have been in config as far as i can tell
        # config = dict(ctx.Config())
        signer = oci.auth.signers.get_resource_principals_signer()
        secrets_client = oci.secrets.SecretsClient({}, signer=signer)
        
        apitoken_content = secrets_client.get_secret_bundle_by_name(secret_name="ipaas-client-secret-2",
            vault_id="ocid1.vault.oc1.uk-london-1.d5sitxohaaa6k.abwgiljtbl5pupmmj3haubob3hb475qozryypozwtr7ukjw4wa46qvcmocya").data.secret_bundle_content.content.encode('utf-8')
        
        apitoken_secret = base64.b64decode(apitoken_content).decode("utf-8")
        print("INFO: Decrypting ipaas-client-secret-2", apitoken_secret, flush=True)
    except (Exception, ValueError) as ex:
        print("ERROR: Decrypting ipaas-client-secret-2", ex, flush=True)

    return response.Response(
        ctx, response_data=json.dumps({"ipaas-client-secret-2": "{0}".format(apitoken_secret)}),
        headers={"Content-Type": "application/json"}
    )

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
