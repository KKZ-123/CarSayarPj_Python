import json
import sys
import psycopg2
import psycopg2.extras
from psycopg2 import sql
import os
import boto3
import shared

aws_region = 'ap-southeast-1'

lambda_client = boto3.client(
    "lambda",
    aws_access_key_id=shared.ACCESS_ID,
    aws_secret_access_key=shared.SECRET_KEY,
    region_name=aws_region
)


def lambda_handler(event, context):
    connection = ''
    try:
        body = json.loads(event['body'])
        if 'bookingkey' in body and 'passengerkey' in body and 'type' in body:
            bookingkey = body['bookingkey']
            passengerkey = body['passengerkey']
            status = body['type']
            connection = shared.connectDB()
            cursor = connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            bookingstatus = shared.REJECT_BY_PASSENGER
            if status == 1:
                bookingstatus = shared.ACCEPT_BY_PASSENGER
            query = sql.SQL(
                'UPDATE {booking} set status = %s WHERE {bookingkey} = %s AND {passengerkey} = %s AND {status} = %s '
            ).format(
                booking=sql.Identifier('booking'),
                bookingkey=sql.Identifier('bookingkey'),
                passengerkey=sql.Identifier('passengerkey'),
                status=sql.Identifier('status')
            )
            cursor.execute(query, (bookingstatus, bookingkey, passengerkey, shared.ACCESS_BY_DRIVER))
            rowcount = cursor.rowcount

            connection.commit()
            if rowcount > 0:
                send_to_driver(bookingkey, status, cursor)
                add_to_history(bookingkey, cursor)
                # current_locations(bookingkey, cursor)
                connection.commit()
                return shared.cb(200, {
                    'returncode': '300',
                    'message': 'Success',
                    'data': current_locations(bookingkey, cursor)
                })
        return shared.cb(200, {
            'returncode': '400',
            'message': 'Invalid booking'
        })

    except Exception as e:
        response = {
            'returncode': '200',
            "message": "Database Error",
            "error": "{} error on line {}".format(e, sys.exc_info()[-1].tb_lineno),
        }
        return shared.cb(200, response)
    finally:
        if connection:
            cursor.close()
            connection.close()


def add_to_history(bookingkey, cursor):
    query = sql.SQL(
        '''
        INSERT INTO bookinghistory(bookingkey, taxigroupkey, riderid, vehicleno, status)
        SELECT booking.bookingkey, booking.taxigroupkey, booking.riderid, riderusers.vehicleno, booking.status
        FROM booking INNER JOIN riderusers ON booking.riderid = riderusers.riderid WHERE booking.bookingkey = %s
        '''
    )
    cursor.execute(query, (bookingkey,))


def current_locations(bookingkey, cursor):
    query = sql.SQL(
        '''
        SELECT lat, lng from ridercurrentlocations 
        INNER JOIN booking on booking.riderid = ridercurrentlocations.riderid where bookingkey = %s
        '''
    )
    cursor.execute(query, (bookingkey,))
    result = cursor.fetchone()
    return result




def send_to_driver(bookingkey, status, cursor):
    query = sql.SQL(
        '''
        SELECT {riderusers}.{fbtoken}, {booking}.{status}, {booking}.{from_lat}, {booking}.{from_lng}, {booking}.{to_lat}, 
        {booking}.{to_lng}, {booking}.{from_loc} as from_loc, {booking}.{to_loc} as to_loc, {booking}.{remark} 
        FROM {booking} INNER JOIN {riderusers} ON {booking}.{riderid} = {riderusers}.{riderid}
        WHERE {booking}.{bookingkey} = %s AND {booking}.{status} IN %s
        '''
    ).format(
        riderusers=sql.Identifier(shared.rideruserTable),
        fbtoken=sql.Identifier('fbtoken'),
        booking=sql.Identifier('booking'),
        from_lat=sql.Identifier('from_lat'),
        from_lng=sql.Identifier('from_lng'),
        to_lat=sql.Identifier('to_lat'),
        to_lng=sql.Identifier('to_lng'),
        from_loc=sql.Identifier('from_loc'),
        to_loc=sql.Identifier('to_loc'),
        remark=sql.Identifier('remark'),
        riderid=sql.Identifier('riderid'),
        bookingkey=sql.Identifier('bookingkey'),
        status=sql.Identifier('status')
    )
    cursor.execute(query, (bookingkey, (shared.ACCEPT_BY_PASSENGER, shared.REJECT_BY_PASSENGER)))
    result = cursor.fetchone()
    if result is not None:
        function_name = os.environ['SEND_NOTI_FUNCTION']
        status = result['status']
        result['status'] = 'accepted' if status == 1 else 'canceled'
        payload = {
            'type': 'acceptdriverbypassenger',
            'body': result
        }
        print(payload)
        lambda_client.invoke(
            FunctionName=function_name,
            InvocationType='Event',
            Payload=json.dumps(payload)
        )
