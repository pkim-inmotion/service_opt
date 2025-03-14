from flask import Flask, request, jsonify
import qrcode
from qrcode.image.styledpil import StyledPilImage
import random
import string
import base64
import io
import os
from google.cloud import storage
from google.cloud.sql.connector import Connector, IPTypes
import tempfile
import datetime
import sqlalchemy
import json
import time
import hmac  


app = Flask(__name__)

# Basic infos (You might want to set these via environment variables)
auth_type = 'totp'
#testing cloud build CI/CD

# Setting Google Storage services instances
storage_client = storage.Client()
bucket_name = os.environ.get('BUCKET_NAME', 'bco_popular_authenticator') # Get from env or default
logo_folder = 'logo/'

def qr_string(mail, issuer):
    pass_temp = ''.join(random.choice(string.ascii_letters) for _ in range(48))
    pass_string = pass_temp[:24] + mail + pass_temp[24:]
    b32_string = base64.b32encode(bytearray(pass_string, 'ascii')).decode('utf-8').replace('=', '')
    qr_code_string = f"otpauth://{auth_type}/{issuer}:{mail}?secret={b32_string}&issuer={issuer}"
    return qr_code_string, b32_string


def get_logo(logo_file_name):
    bucket = storage_client.get_bucket(bucket_name)
    blob_logo = bucket.blob(f"{logo_folder}{logo_file_name}")

    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file_path = temp_file.name

    blob_logo.download_to_filename(temp_file_path)
    return temp_file_path


def connect_cloud_postgres():
    instance_connection_name = os.environ["INSTANCE_CONNECTION_NAME"]
    db_name = os.environ["DB_NAME"]
    db_user = os.environ["DB_USER"]
    ip_type = IPTypes.PRIVATE if os.environ.get("PRIVATE_IP") else IPTypes.PUBLIC

    connector = Connector(ip_type)

    conn = connector.connect(
        instance_connection_name,
        "pg8000",
        db=db_name,
        user=db_user,
        enable_iam_auth=True
    )

    return conn


def get_pass_strings(uid):
    #connect to cloud sql postgres
    pool = sqlalchemy.create_engine(
        "postgresql+pg8000://",
        creator = connect_cloud_postgres
    )

    select_query = sqlalchemy.text(
        """
            SELECT 
                user_key

            FROM
                authenticator.auth_data

            WHERE
                auth_key = :uid
        """
    )

    select_param = {"uid": f"{uid}"}

    #excecute the select query
    with pool.connect() as db_conn:
        results = db_conn.execute(select_query, parameters=select_param).fetchall()
        db_conn.close()

    #check the results
    if len(results) == 0:
        return "empty"
    else:
        return results[0][0]


def gen_digits(b32_key):
    b32_key = b32_key + '='*(8-(len(b32_key)%8))
    #print(b32_key)
    #decode b32_key
    byte_key = base64.b32decode(b32_key, True)

    #generate codes
    now = int(time.time() // 30)
    msg = now.to_bytes(8, "big")
    digest = hmac.new(byte_key, msg, "sha1").digest()
    offset = digest[len(digest)-1] & 0xF
    code = digest[offset : offset + 4]
    code = int.from_bytes(code, "big") & 0x7FFFFFFF
    code = code % 1000000
    final_code = "{:06d}".format(code)

    return final_code



@app.route('/genqr', methods=['POST'])
def generate_qrcode():
    request_json = request.get_json(silent=True)

    if not request_json or 'mail' not in request_json or 'id' not in request_json or 'institution' not in request_json or 'image_name' not in request_json:
        return jsonify({"error": "Missing required parameters."}), 400

    mail = request_json['mail']
    uid = request_json['id']
    issuer = request_json['institution']
    logo_file_name = request_json['image_name']

    qr_code_string, b32_string = qr_string(mail, issuer)
    qr_image = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_H, box_size=5)
    qr_image.add_data(qr_code_string)

    logo_path = get_logo(logo_file_name)
    qr_image = qr_image.make_image(image_factory=StyledPilImage, embeded_image_path=logo_path)

    img_buffer = io.BytesIO()
    qr_image.save(img_buffer, format="PNG")
    qr_b64 = "data:image/png;base64,"+base64.b64encode(img_buffer.getvalue()).decode("utf-8")

    ct = datetime.datetime.now()

    pool = sqlalchemy.create_engine(
        "postgresql+pg8000://",
        creator=connect_cloud_postgres
    )

    insert_query = sqlalchemy.text(
        """
            INSERT INTO authenticator.auth_data
            (
                auth_key,
                user_mail,
                user_key,
                image_base64,
                insert_date
            )
            VALUES
            (
                :auth_key,
                :user_mail,
                :user_key,
                :image_base64,
                :insert_date
            )
        """
    )

    insert_param = {"auth_key": f"{uid}", "user_mail": f"{mail}", "user_key": f"{b32_string}", "image_base64": f"{qr_b64}", "insert_date": ct}

    with pool.connect() as db_conn:
        db_conn.execute(insert_query, parameters=insert_param)
        db_conn.commit()

    return jsonify({"qr_code_image": f"{qr_b64}"})


@app.route('/codecheck', methods=['POST'])
def compare_digits():
    request_json = request.get_json(silent=True)
    
    #get the required infos
    uid = request_json['id']
    input_code = request_json['codes']

    #print(uid)
    #print(input_code)

    #get the key strings
    b32_key = get_pass_strings(uid)
    #print(b32_key)

    #process the b32_key
    if b32_key == "empty":
        return {"result": {"return_code": -1, "message": "id not found"}, "is_same": False}
    else:
        final_code = gen_digits(b32_key)

        if final_code == input_code:
            return {"result": {"return_code": 0, "message": "successful"}, "is_same": True}
        else:
            return {"result": {"return_code": -2, "message": "codes not match"}, "is_same": False}
        



if __name__ == "__main__":
    #app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))
    pass