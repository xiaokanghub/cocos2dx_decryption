import argparse
import gzip
import zlib
import io
import sys
from typing import Optional
from zipfile import BadZipFile, ZipFile
import xxtea
from reversebox.common.logger import get_logger
from reversebox.io_files.check_file import check_file

logger = get_logger(__name__)

def export_data(
    jsc_file_path: str, encryption_key_str: str, output_file_path: str
) -> Optional[tuple]:
    """
    Function for decrypting JSC files
    """
    logger.info("Starting export_data...")

    code, status = check_file(jsc_file_path, ".JSC", True)
    if code != "OK":
        return code, status

    jsc_file = open(jsc_file_path, "rb")
    jsc_file_data = jsc_file.read()
    jsc_file.close()

    logger.info(f"Decrypting with key = {encryption_key_str}")
    output_data = xxtea.decrypt(jsc_file_data, encryption_key_str, padding=False)
    if len(output_data) == 0:
        return "WRONG_KEY", "Invalid encryption key!"

    is_gzip_file = True
    try:
        output_data = zlib.decompress(output_data, 32 + 15)
        logger.info("IT IS a GZIP archive.")
    except zlib.error as error:
        logger.info("It's NOT a GZIP archive.")
        is_gzip_file = False

    if not is_gzip_file:
        try:
            zip_file = io.BytesIO(output_data)
            ZipFile(zip_file)
            output_file_path += ".zip"
            logger.info("IT IS a ZIP archive.")
        except BadZipFile as error:
            logger.info("It is NOT a ZIP archive.")

    js_file = open(output_file_path, "wb")
    js_file.write(output_data)

    js_file.close()
    logger.info(f"File exported: {output_file_path}")
    return "OK", ""

if __name__ == '__main__':
    enc_jsc_file_path = "C:\\Users\\12649\\Desktop\\jsc\\md5.jsc"
    dec_jsc_file_path = "C:\\Users\\12649\\Desktop\\jsc\\md5_dec.js"
    dec_key = "bc337194-20c1-45"
    code, status = export_data(enc_jsc_file_path, dec_key, dec_jsc_file_path)