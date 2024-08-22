import json
import sys
import psycopg2
import psycopg2.extras
from psycopg2 import sql
import shared


def lambda_handler(event, context):
    connection = ''
    try:

        body = json.loads(event['body'])

        params = event['queryStringParameters']

        if params is not None and 'page_size' in params:
            page_size = params['page_size']
            if not page_size.isdigit():
                return shared.cb(200, {
                    'returncode': '200',
                    'message': 'Invalid pager'
                })

            if 'bookingid' in body:
                bookingid = body['bookingid']
                autoid = int(body['autoid'])
                condition_val = []
                connection = shared.connectDB()
                cursor = connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

                query = (
                    """
                        SELECT DISTINCT
                            booking.bookingkey,
                            booking.passengerkey as passengerid,
                            booking.riderid,
                            riderusers.username as rider_name,
                            passengers.name as passenger_name
                        FROM booking
                        INNER JOIN riderusers ON booking.riderid = riderusers.riderid
                        LEFT JOIN passengers ON passengers.passengerkey = booking.passengerkey
                        LEFT JOIN chat_message ON chat_message.bookingkey = booking.bookingkey
                        WHERE booking.bookingkey = %s
                    """
                )

                cursor.execute(sql.SQL(query), (bookingid,))

                data = cursor.fetchone()

                if data is not None:

                    message_query = (
                        """
                        SELECT DISTINCT
                            chat_message.person_key as senderid,
                            chat_message.message,
                            chat_message.createddate,
                            chat_message.autoid 
                            FROM booking
                            INNER JOIN riderusers ON booking.riderid = riderusers.riderid
                            INNER JOIN passengers ON passengers.passengerkey = booking.passengerkey
                            INNER JOIN chat_message ON chat_message.bookingkey = booking.bookingkey
                            WHERE booking.bookingkey = %s
                            
                        """
                    )
                    condition_val.append(bookingid)

                    if autoid != 0:
                        message_query += " AND chat_message.autoid < %s "
                        condition_val.append(autoid)

                    message_query += " ORDER BY chat_message.autoid DESC LIMIT %s"
                    condition_val.append(page_size)
                    cursor.execute(sql.SQL(message_query), (tuple(condition_val)))
                    message_data = cursor.fetchall()

                    if message_data is not None:
                        data['chat'] = message_data

                    else:
                        data['chat'] = []
                    res = {
                        "returncode": "300",
                        "message": "Success",
                        "data": data,
                        "total_count": get_total_count(bookingid, cursor)
                    }
                    cursor.close()
                    connection.close()
                    return shared.cb(200, res)
                else:

                    res = {
                        "returncode": "200",
                        "message": "No Data"
                    }

                    return shared.cb(200, res)

        else:
            response = {"returncode": "200", "message": "Unauthorized Access"}
            return shared.cb(200, response)

    except Exception as e:
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


def get_total_count(bookingid, cursor):
    query = (
        """
        SELECT count(*) as total_count
        FROM chat_message
        WHERE chat_message.bookingkey = %s
        """
    )
    cursor.execute(query, (bookingid,))
    result = cursor.fetchone()
    return result['total_count'] if result is not None else 0
