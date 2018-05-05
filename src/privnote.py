# -*- coding: utf-8 -*-
import os
import tempfile
import base64
import hashlib

import logging
logging.basicConfig(level=os.environ.get("APP_LOGLEVEL", "INFO"))
logger = logging.getLogger(__name__)


# generate a random temp dir filename but don't create or open it
def generate_random_tempfilename():
    rand = base64.urlsafe_b64encode(
        hashlib.md5(os.urandom(128)).digest()
    )[:16]
    return os.path.join(tempfile.gettempdir(), '.{}'.format(hash(os.times())))


# relies on privnote-cli and node.js being installed in the Dockerfile
# https://github.com/nonrational/privnote-cli
def generate_privnote_url(note):
    logger.info("Generating privnote")
    # write the privnote out to disk
    temp_note_file = tempfile.NamedTemporaryFile(delete=False, mode="w")
    temp_note_file.write(str(note))
    temp_note_file.close()

    # execute it
    privnote_filename = generate_random_tempfilename()
    os.system(f"privnote < {temp_note_file.name} > {privnote_filename}")

    # read the privnote from disk
    with open(privnote_filename, "r") as privnote_file:
        privnote_link = privnote_file.read()

    # cleanup
    os.remove(temp_note_file.name)
    os.remove(privnote_filename)

    logger.info(f"Generated privnote url: {privnote_link}")
    return privnote_link
