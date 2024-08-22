import json
import boto3
from botocore.exceptions import ClientError
import urllib3
import sys
import secrets
import datetime
import dateutil.tz
import random as r
import threading
import time
import re
import base64
import urllib.parse
import os
import psycopg2
import psycopg2.extras
import uuid
from psycopg2 import sql
import jwt
import datetime as date1
from decimal import Decimal
from datetime import datetime, timedelta
import datetime as date1
import shared

# For mobile number normalization
mobile_code = "(09)"
country_code = "(\\+?959)"
ooredoo = "(?:9(?:9|8|7|6|5|4|3|2|1)\\d{7})$"
mytel = "(?:6(?:9|8|7|6|5|4|3|2|1)\\d{7})$"
telenor = "(?:7(?:9|8|7|6|5|4|3|2|1)\\d{7})$"
mpt_2_series = "2\\d{6,8}"
mpt_3_series = "3\\d{7,8}"
mpt_4_series = "4\\d{7,8}"
mpt_5_series = "5\\d{6}"
mpt_6_series = "6\\d{6}"
mpt_7_series = "7\\d{7}"
mpt_8_series = "8\\d{6,8}"
mpt_9_series = "9(?:0|1|9)\\d{5,6}"
mpt = "(?:{}|{}|{}|{}|{}|{}|{}|{})$".format(mpt_2_series, mpt_3_series,
                                            mpt_4_series, mpt_5_series,
                                            mpt_6_series, mpt_7_series,
                                            mpt_8_series, mpt_9_series)

all_operators_re = "({0}|{1}|{2}|{3})".format(ooredoo, telenor, mpt, mytel)

mm_phone_re = re.compile("^({0}|{1})?{2}".format(country_code, mobile_code,
                                                 all_operators_re))

phone_re = re.compile("^\\+(?:[0-9]?){6,14}[0-9]$")
regex_email = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'


def is_valid_phonenumber(phonenumber):
    phonenumber = str(phonenumber).strip()
    return mm_phone_re.match(phonenumber) is not None


def validate_email_format(email):
    # pass the regular expression
    # and the string into the fullmatch() method
    if (re.fullmatch(regex_email, email)):
        return "true"
    else:
        return "false"


def normalize_phonenumber(phonenumber):
    phonenumber = str(phonenumber).strip()
    match = mm_phone_re.match(phonenumber)
    if not match:
        raise RuntimeError("%s is not a valid Myanmar phonenumber." %
                           phonenumber)

    phonenumber = match.groups()[3]
    phonenumber = '959' + phonenumber
    return int(phonenumber)


def return_message(code, desc):
    response_json = {"returncode": code,
                     "message": desc
                     }
    return {
        'statusCode': 200,
        'headers': {
            'Access-Control-Allow-Headers': 'Content-Type',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
        },
        'body': json.dumps(response_json)
    }


#
def connect2():
    dbname = os.environ['dbname']
    dbuser = os.environ['dbuser']
    dbhost = os.environ['dbhost']
    dbpassword = os.environ['dbpassword']
    dbport = os.environ['dbport']
    con = psycopg2.connect(dbname=dbname, user=dbuser, host=dbhost,
                           password=dbpassword, port=dbport)
    return con


def call_checkOTPapi(phonenooremail, otp, otpsession, isphoneoremail):
    http = urllib3.PoolManager()
    if isphoneoremail == "1":
        url = "https://mxgw.omnicloudapi.com/sms/checkotp"
        payload = {'appid': '002', 'accesskey': '445fdc4bd21cbcd5', 'phoneno': phonenooremail, 'otp': otp,
                   'otpsession': otpsession}
    elif isphoneoremail == "2":
        url = "https://mxgw.omnicloudapi.com/email/checkotp"
        payload = {"appid": "002", "accesskey": "445fdc4bd21cbcd5", "toemail": phonenooremail, "otp": otp,
                   "otpsession": otpsession}

    encoded_data = json.dumps(payload).encode('utf-8')
    header = {'Content-Type': 'application/json'}

    response = http.request(
        'POST',
        url,
        body=encoded_data,
        headers=header)
    return response


def select_and_insert_related_data(riderid):
    con = shared.connectDB()
    cursor = con.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    cursor.execute("SELECT mobile, vehicleno FROM riderusers WHERE riderid = %s", (riderid,))
    row = cursor.fetchone()

    if row is not None:
        mobile = row.get('mobile', '')
        vehicleno = row.get('vehicleno', '')

        if vehicleno is None:
            vehicleno = ''

        insert_into_drivermobilehistory(cursor, riderid, mobile)
        insert_into_drivervehiclehistory(cursor, riderid, vehicleno)

    con.commit()
    cursor.close()
    con.close()


def generateSysKey():
    return uuid.uuid4().hex


def getcreatedate():
    return date1.datetime.now()


def insert_into_drivermobilehistory(cursor, riderid, mobile):
    drivermobilehistorykey = generateSysKey()
    createddate = getcreatedate()

    cursor.execute(
        "INSERT INTO drivermobilehistorys (drivermobilehistorykey,riderid,mobile, createdby,createddate ,modifiedby, modifieddate) VALUES (%s, %s, %s, %s, %s, %s, %s)",
        (drivermobilehistorykey, riderid, mobile, riderid, createddate, riderid, createddate))


def insert_into_drivervehiclehistory(cursor, riderid, vehicleno):
    drivervehiclehistorykey = generateSysKey()
    createddate = getcreatedate()

    cursor.execute(
        "INSERT INTO drivervehiclehistorys (drivervehiclehistorykey,riderid,vehicleno, createdby,createddate ,modifiedby, modifieddate) VALUES (%s, %s, %s, %s, %s, %s, %s)",
        (drivervehiclehistorykey, riderid, vehicleno, riderid, createddate, riderid, createddate))


def lambda_handler(event, context):
    try:
        body = json.loads(event["body"])

        if "phonenooremail" not in body and "riderid" not in body and "otp" not in body and "otpsession" not in body:
            response = {
                "returncode": "200",
                "message": "Unauthorized Access"
            }
            return shared.cb(200, response)

        phonenooremail = body['phonenooremail']
        riderid = body['riderid']
        otp = body["otp"]
        otpsession = body['otpsession']
        phone_uuid = body.get('uuid', '')
        version = body.get('version', '0')
        platform = body.get('platform', '1')

        # Parameters Validation
        if riderid == '':
            code = "210"
            desc = "Invalid Request"
            return return_message(code, desc)
        elif phonenooremail == '':
            code = "210"
            desc = "Invalid Request"
            return return_message(code, desc)
        elif otp == '':
            code = "210"
            desc = "Invalid Request"
            return return_message(code, desc)
        elif otpsession == '':
            code = "210"
            desc = "Invalid Request"
            return return_message(code, desc)

        # Normalize Phone Number
        if is_valid_phonenumber(phonenooremail):
            phonenooremail = str(normalize_phonenumber(phonenooremail))
            isphoneoremail = "1"
        else:
            if validate_email_format(phonenooremail) == "true":
                isphoneoremail = "2"
            else:
                code = "210"
                desc = "Invalid Request"
                return return_message(code, desc)
        con = shared.connectDB()
        cursor = con.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        query = (
            """
            select t2 from conflit_otp
            """
        )
        cursor.execute(query, )
        data = cursor.fetchone()
        otp_limit_wrong_count = int(data['t2'])
        # otp by pass for iOS
        if phonenooremail == '959795767364':
            if otp == '134562':
                permissions = get_rider_group_with_permission('959795767364', cursor)
                a_token = generate_token(riderid, permissions, 1, version, platform)
                r_token = generate_token(riderid, permissions, 2, version, platform)
                return cb(200, {
                    'returncode': '300',
                    'message': 'Successful',
                    'token': a_token,
                    'refresh_token': r_token
                })
            else:
                response = call_checkOTPapi(phonenooremail, otp, otpsession, isphoneoremail)
                returncode = json.loads(response.data.decode('utf-8'))['returncode']
                message = json.loads(response.data.decode('utf-8'))['message']
        else:
            query = (
                """
                select otp_wrong_count,date(otp_wrong_date) as otp_wrong_date from riderusers where mobile=%s
                """
            )
            cursor.execute(query, (phonenooremail,))
            result = cursor.fetchone()
            if result and result['otp_wrong_count'] == otp_limit_wrong_count and result[
                'otp_wrong_date'] == datetime.now().date():
                return shared.cb(200, {
                    "returncode": "200",
                    "message": "You have reached OTP wrong limit for today. Please try again in next day or contact to admin."
                })
            # call check otp api
            response = call_checkOTPapi(phonenooremail, otp, otpsession, isphoneoremail)
            returncode = json.loads(response.data.decode('utf-8'))['returncode']
            message = json.loads(response.data.decode('utf-8'))['message']

        if returncode == '300':
            # update status in db

            con = shared.connectDB()
            cursor = con.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            sql_query = "update riderusers set status = %s,t1=%s where riderid = %s and userid = %s"

            idata = (7, phone_uuid, riderid, phonenooremail)
            cursor.execute(sql_query, idata)
            con.commit()
            if cursor.rowcount > 0:
                isvalid = "7"
            else:
                isvalid = "0"

            if isvalid == "0":
                code = "220"
                desc = "Server Error"
                return return_message(code, desc)
            else:
                select_and_insert_related_data(riderid)

                # if mobile and vehicleno:
                #     insert_into_drivermobilehistory(cursor, riderid, mobile)
                #     insert_into_drivervehiclehistory(cursor, riderid, vehicleno)
                permissions = get_rider_group_with_permission(riderid, cursor)
                if len(permissions) == 0:
                    # add rider to default group
                    # default taxigroupkey c4c4344819d848e6b9bcce268893592e

                    cursor.execute(
                        sql.SQL("SELECT taxigroupkey FROM taxigroups WHERE is_default = 1;")
                    )
                    default_taxigroup_keys = cursor.fetchall()

                    for default_taxigroup_key in default_taxigroup_keys:
                        result = get_member_id(cursor, default_taxigroup_key['taxigroupkey'])
                        permissions[default_taxigroup_key['taxigroupkey']] = '0'
                        memberid = '0001'
                        if result is not None:
                            memberid = f'{result:04}'

                        cursor.execute(
                            sql.SQL(
                                "INSERT INTO {table} ({drivertaxigroupkey},{riderid},{taxigroupkey},{createdby},{createddate},{modifiedby},{modifieddate},{memberid}) VALUES (%s,%s,%s,%s,%s,%s,%s,%s);"
                            ).format(
                                table=sql.Identifier('drivertaxigroups'),
                                drivertaxigroupkey=sql.Identifier("drivertaxigroupkey"),
                                riderid=sql.Identifier("riderid"),
                                taxigroupkey=sql.Identifier("taxigroupkey"),
                                createdby=sql.Identifier("createdby"),
                                createddate=sql.Identifier("createddate"),
                                modifiedby=sql.Identifier("modifiedby"),
                                modifieddate=sql.Identifier("modifieddate"),
                                memberid=sql.Identifier("memberid"),
                            ),
                            (
                                generateSysKey(),
                                riderid,
                                default_taxigroup_key['taxigroupkey'],
                                riderid,
                                getcreatedate(),
                                riderid,
                                getcreatedate(),
                                memberid
                            ),
                        )
                        con.commit()
                    cursor.close()
                    con.close()

                a_token = generate_token(riderid, permissions, 1, version, platform)
                r_token = generate_token(riderid, permissions, 2, version, platform)
                return cb(200, {
                    'returncode': '300',
                    'message': 'Successful',
                    'token': a_token,
                    'refresh_token': r_token
                })
        else:
            # for wrong otp code
            otp_wrong_query = (
                """
                select otp_wrong_count,otp_wrong_date from riderusers where mobile=%s
                """
            )
            cursor.execute(otp_wrong_query, (phonenooremail,))
            result = cursor.fetchone()
            if result:
                query = (
                    """
                    update riderusers set otp_wrong_count = %s, otp_wrong_date = now() where mobile=%s
                    """
                )
                if isinstance(result['otp_wrong_date'], str):
                    result['otp_wrong_date'] = datetime.strptime(result['otp_wrong_date'],
                                                                 '%Y-%m-%dT%H:%M:%S.%f').date()
                if result['otp_wrong_count'] < otp_limit_wrong_count and result[
                    'otp_wrong_date'].date() == datetime.now().date():
                    otp_wrong_count = result['otp_wrong_count'] + 1
                    cursor.execute(query, (otp_wrong_count, phonenooremail))
                elif result['otp_wrong_date'].date() < datetime.now().date():
                    cursor.execute(query, (1, phonenooremail))
                else:
                    return shared.cb(200, {
                        "returncode": "200",
                        "message": "You have reached OTP wrong limit for today. Please try again in next day or contact to admin."
                    })
                con.commit()
            code = returncode
            desc = message
            return return_message(code, desc)

    except Exception as e:
        response = {
            "returncode": "220",
            "message": "Server Error",
            "error": "{} error on line {}".format(e, sys.exc_info()[-1].tb_lineno),
        }
        return cb(200, response)


def generate_token(riderid, permissions, type, version, platform):
    # token_secret = get_token_secret()
    secret_key = 'F1aX1%J0J3SeRv1CE-KEY2wT'
    refresh_key = '4CGfXhd6#$N@sk^#4a3&~Q5T2D4u,KeGWW:^w*%#yc74B68p37'
    days = date1.timedelta(days=30)
    minutes = date1.timedelta(minutes=15)

    if type == 1:
        return jwt.encode(
            {
                "userid": riderid,
                "userdata": permissions,
                "exp": date1.datetime.utcnow() + minutes,
            },
            secret_key,
        )
    else:
        return jwt.encode(
            {
                "userid": riderid,
                "userdata": permissions,
                "exp": date1.datetime.utcnow() + days,
                "version": version,
                "platform": platform
            },
            refresh_key,
        )


def get_rider_group_with_permission(riderid, cursor):
    query = sql.SQL(
        'SELECT {taxigroupkey}, {isadmin} FROM {table} WHERE {riderid} = %s '
    ).format(
        taxigroupkey=sql.Identifier('taxigroupkey'),
        isadmin=sql.Identifier('isadmin'),
        table=sql.Identifier('drivertaxigroups'),
        riderid=sql.Identifier('riderid')
    )
    cursor.execute(query, (riderid,))
    result = cursor.fetchall()
    if result:
        return {data['taxigroupkey']: str(data['isadmin']) for data in result}
    return {}


def get_token_secret():
    secret = get_secret("flaxi/key")
    if "secret_key" in secret and 'pass_enc_key' in secret:
        return secret
    else:
        return {
            "secret_key": "",
            "pass_enc_key": ""
        }


def get_secret(secret_name):
    try:
        region_name = 'ap-southeast-1'
        session = boto3.session.Session()
        client = session.client(
            service_name='secretsmanager',
            region_name=region_name
        )

        try:
            get_secret_value_response = client.get_secret_value(SecretId=secret_name)
            secret = ""
            if 'SecretString' in get_secret_value_response:
                secret = get_secret_value_response['SecretString']
            else:
                decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])
            return json.loads(secret)
        except ClientError as e:
            response = {
                'returncode': '200',
                "status": "Server Error",
                "error": '{} error on line {}'.format(e, sys.exc_info()[-1].tb_lineno)
            }
            return json.loads(response)
    except Exception as e:
        response = {
            'returncode': '200',
            "status": "Server Error",
            "error": '{} error on line {}'.format(e, sys.exc_info()[-1].tb_lineno)
        }
        return json.loads(response)


def cb(statuscode, body):
    return {
        'statusCode': int(statuscode),
        'headers': {
            'Access-Control-Allow-Headers': 'Content-Type,Authorization',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
        },
        'body': json.dumps(body, default=default)
    }


def default(obj):
    if isinstance(obj, Decimal):
        return str(obj)
    if isinstance(obj, (datetime, datetime.date)):
        return obj.isoformat()
    raise TypeError("Object of type '%s' is not JSON serializable" % type(obj).__name__)


def get_member_id(cur, taxigroupkey):
    query = sql.SQL(
        "SELECT (CAST({memberid} AS INT) + 1) AS incremented_memberid FROM {drivertaxigroupsTable} WHERE {taxigroupkey} = %s ORDER BY autoid DESC LIMIT 1;"
    ).format(
        drivertaxigroupsTable=sql.Identifier('drivertaxigroups'),
        memberid=sql.Identifier("memberid"),
        taxigroupkey=sql.Identifier("taxigroupkey")
    )
    cur.execute(query, (taxigroupkey,))
    result = cur.fetchone()

    if result:
        return result['incremented_memberid']
    else:
        return None
