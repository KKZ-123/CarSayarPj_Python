import json
import sys
import psycopg2
import psycopg2.extras
from psycopg2 import sql
import shared
import os
import boto3
import firebase_admin
from firebase_admin import credentials, messaging

aws_region = 'ap-southeast-1'

lambda_client = boto3.client(
    "lambda",
    aws_access_key_id=shared.ACCESS_ID,
    aws_secret_access_key=shared.SECRET_KEY,
    region_name=aws_region
)

client = boto3.client('apigatewaymanagementapi',
                      endpoint_url="https://takmzujdyc.execute-api.ap-southeast-1.amazonaws.com/v1")


def lambda_handler(event, context):
    connection = ''
    if not firebase_admin._apps:
        cred = credentials.Certificate("credentials.json")
        firebase_admin.initialize_app(cred)
    try:
        body = json.loads(event["body"])
        key_list = ['bookingkey', 'riderid']
        select_fields = ['riderusers.username', 'riderusers.vehicleno', 'booking.passengerkey', 'riderusers.photo',
                         'taxigroups.groupname', 'ridercurrentlocations.lat', 'ridercurrentlocations.lng',
                         'booking.from_lat', 'booking.from_lng', 'taxigroups.arrival_rate']

        if all(name in body.keys() for name in key_list):
            bookingkey = body.get('bookingkey', '')
            riderid = body.get('riderid', '')
            special_taxigroupkey = body.get('special_taxigroupkey', '')
            taxigroupkey = body.get('taxigroupkey', '')
            status = 2
            modifieddate = shared.getCreateDate()
            modifiedby = 'admin'
            connection = shared.connectDB()
            cursor = connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

            cursor.execute(
                sql.SQL(
                    """
                    select status from booking 
                    where bookingkey = %s
                    """
                ), (bookingkey,)
            )
            check_data = cursor.fetchone()
            check_status = check_data['status']
            if check_status == 4:
                res = {
                    "returncode": "301",
                    "message": "Booking cancelled by Passenger",
                }
                return shared.cb(200, res)
            elif check_status == 2 or check_status == 6:
                res = {
                    "returncode": "301",
                    "message": "This booking has already been accepted by another driver."
                }
                return shared.cb(200, res)
            elif check_status == 400:
                res = {
                    "returncode": "301",
                    "message": "Booking was already expired",
                }
                return shared.cb(200, res)
            else:
                if special_taxigroupkey == '' and taxigroupkey == '':
                    cursor.execute(
                        sql.SQL(
                            "LOCK TABLE booking IN SHARE UPDATE EXCLUSIVE MODE; "
                            "UPDATE {table} SET {riderid} = %s, {modifieddate} = %s, {modifiedby} = %s, {status} = %s "
                            "WHERE bookingkey = %s and status = 1 RETURNING status ;"
                        ).format(
                            table=sql.Identifier("booking"),
                            riderid=sql.Identifier("riderid"),
                            modifieddate=sql.Identifier("modifieddate"),
                            modifiedby=sql.Identifier("modifiedby"),
                            status=sql.Identifier("status"),
                            bookingkey=sql.Identifier("bookingkey")
                        ),
                        (riderid, modifieddate, modifiedby, status, bookingkey)
                    )
                else:
                    cursor.execute(
                        sql.SQL(
                            "LOCK TABLE booking IN SHARE UPDATE EXCLUSIVE MODE; "
                            "UPDATE {table} SET {riderid} = %s, {modifieddate} = %s, {modifiedby} = %s, {status} = %s, "
                            "{taxigroupkey} = %s WHERE bookingkey = %s and status = 1 RETURNING status ;"
                        ).format(
                            table=sql.Identifier("booking"),
                            riderid=sql.Identifier("riderid"),
                            modifieddate=sql.Identifier("modifieddate"),
                            modifiedby=sql.Identifier("modifiedby"),
                            status=sql.Identifier("status"),
                            taxigroupkey=sql.Identifier("taxigroupkey"),
                            bookingkey=sql.Identifier("bookingkey")
                        ),
                        (riderid, modifieddate, modifiedby, status, taxigroupkey, bookingkey)
                    )

                booking_status = cursor.fetchone()
                connection.commit()

                count = cursor.rowcount

                if count > 0:

                    cursor.execute(
                        sql.SQL("SELECT {fields} FROM {table} "
                                "INNER JOIN riderusers on booking.riderid = riderusers.riderid "
                                "INNER JOIN ridercurrentlocations on booking.riderid = ridercurrentlocations.riderid "
                                "INNER JOIN taxigroups on booking.taxigroupkey = taxigroups.taxigroupkey "
                                "WHERE riderusers.{riderid} = %s "
                                "AND {table}.bookingkey = %s AND {table}.status = 2").format(
                            fields=sql.SQL(',').join(map(sql.SQL, tuple(select_fields))),
                            table=sql.Identifier('booking'),
                            riderid=sql.Identifier('riderid')
                        ),
                        (riderid, bookingkey)
                    )

                    row = cursor.fetchone()

                    if row['photo'] != "" and row['photo'] is not None:
                        row['photo'] = getDownloadURL('driver/profile/' + row['photo'])

                    cursor.execute(
                        sql.SQL(
                            """
                            SELECT connectionid FROM {table} WHERE {userkey} = %s and type = 9 order by autoid desc limit 1
                            """
                        ).format(
                            table=sql.Identifier('socketconnections'),
                            userkey=sql.Identifier('userkey')
                        ),
                        (row['passengerkey'],)
                    )
                    result = cursor.fetchone()
                    connectionid = result['connectionid']

                    payload = {
                        'username': row['username'],
                        'vehicleno': row['vehicleno'],
                        'passengerkey': row['passengerkey'],
                        'photo': row['photo'],
                        'groupname': row['groupname'],
                        'bookingkey': bookingkey,
                        'lat': row['lat'],
                        'lng': row['lng'],
                        'from_lat': row['from_lat'],
                        'from_lng': row['from_lng'],
                        'arrival_rate': row['arrival_rate']
                    }

                    function_name = os.environ['SEND_PASSENGER_NOTI_FUNCTION']
                    res = lambda_client.invoke(
                        FunctionName=function_name,
                        InvocationType='Event',
                        Payload=json.dumps(payload)
                    )

                    responseMessage = {
                        'topic': 'driveraccepted',
                        'body': {
                            'status': "accepted",
                            'bookingkey': bookingkey,
                            'vehicleno': row['vehicleno'],
                            'username': row['username'],
                            'lat': row['lat'],
                            'lng': row['lng'],
                            'groupname': row['groupname'],
                            'photo': row['photo']
                        }
                    }
                    try:
                        client.post_to_connection(ConnectionId=connectionid,
                                                  Data=json.dumps(responseMessage).encode('utf-8'))
                    except Exception as e:
                        a = 'b'

                    res = {
                        "returncode": "300",
                        "message": "Success",
                    }
                    return shared.cb(200, res)
                else:
                    if booking_status is not None:
                        check_status = booking_status['status']
                        if check_status == 4:
                            res = {
                                "returncode": "301",
                                "message": "Booking cancelled by Passenger",
                            }
                            return shared.cb(200, res)
                        elif check_status == 2 or check_status == 6:
                            res = {
                                "returncode": "301",
                                "message": "This booking has already been accepted by another driver."
                            }
                            return shared.cb(200, res)
                        elif check_status == 400:
                            res = {
                                "returncode": "301",
                                "message": "Booking was already expired",
                            }
                            return shared.cb(200, res)
                    else:
                        res = {
                            'returncode': '301',
                            'message': 'This booking has already been accepted by another driver.'
                        }
                        return shared.cb(200, res)

        else:
            response = {
                "returncode": "200",
                "message": "Unauthorized Access"
            }
            return shared.cb(200, response)
    except Exception as e:
        if connection:
            connection.rollback()
        response = {
            "returncode": "220",
            "message": "Server Error",
            "error": "{} error on line {}".format(e, sys.exc_info()[-1].tb_lineno),
        }
        return shared.cb(200, response)
    finally:
        if connection:
            cursor.close()
            connection.close()


def getDownloadURL(key):
    _S3Secret = shared.GetBucketSecret()
    s3_client = boto3.client('s3', aws_access_key_id=_S3Secret['access_id'],
                             aws_secret_access_key=_S3Secret['secret_key'])
    url = s3_client.generate_presigned_url(
        'get_object',
        Params={
            'Bucket': "flaxi",
            'Key': key
        },
        ExpiresIn=86400,
        HttpMethod='GET'
    )
    return url
