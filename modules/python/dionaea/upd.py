import os
import logging
import json
import time
import datetime
import calendar
import MySQLdb
import geoip2.database
import requests

def update_base():

    config = {
        "database": "dionaea",
        "user": "root"
        "password": "root"
        "host": "127.0.0.1"
        "port": "3306"
        "vtapikey": ""
    }

    try:
        dbh = MySQLdb.connect(host=config['host'], user=config['user'], passwd=config['password'], db=config['database'], port=int(config['port']), charset="utf8", use_unicode=True)
    except:
        print("Unable to connect the database")

    cursor = dbh.cursor()


    files = os.listdir("/opt/dionaea/var/lib/dionaea/binaries/")
    print("!!!!!!!!!!!!!!!!!!!1", files)
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    for f in files:
        md5 = f
        is_exist = cursor.execute("SELECT virustotal_md5_hash FROM virustotals  WHERE virustotal_md5_hash='%s'" % md5)
        if is_exist == 0: 
            params = {'apikey': config['vtapikey'], 'resource': md5}
            try:
                response = requests.get(url, params=params)
                j = response.json()
            except:
                j = {'response_code': -2}

            print(j)

            if j['response_code'] == 1: # file was known to virustotal
                permalink = j['permalink']
                # Convert UTC scan_date to Unix time  
                date = calendar.timegm(time.strptime(j['scan_date'], '%Y-%m-%d %H:%M:%S'))
                try:            
                    cursor.execute("INSERT INTO virustotals (virustotal_md5_hash, virustotal_permalink, virustotal_timestamp) VALUES (%s,%s,%s)",
                                        (md5, permalink, date))
                except Exception as e:
                    print(e)

                dbh.commit()

                virustotal = cursor.lastrowid

                scans = j['scans']
                for av, val in scans.items():
                    res = val['result']
                    # not detected = '' -> NULL
                    if res == '':
                        res = None
                    try:
                        cursor.execute("""INSERT INTO virustotalscans (virustotal, virustotalscan_scanner, virustotalscan_result) VALUES (%s,%s,%s)""",
                                            (virustotal, av, res))
                    except Exception as e:
                        print(e)
                   
                    logger.debug("scanner {} result {}".format(av,scans[av]))
                dbh.commit()

            time.sleep(25)
