from dionaea import IHandlerLoader
from dionaea.core import ihandler

import os
import logging
import json
import time
import datetime
import calendar
import MySQLdb
import geoip2.database
import requests


logger = logging.getLogger('log_mysql')
logger.setLevel(logging.DEBUG)


def if_not_exist_index(self, tbl_name, idx_name):
        x = self.cursor.execute("""SELECT COUNT(1) IndexIsThere 
            FROM INFORMATION_SCHEMA.STATISTICS
            WHERE table_schema=DATABASE() AND table_name='%s' AND index_name='%s';""" % (tbl_name, idx_name))
        if x == 0:
            return True
        else:
            return False


class LogSQLHandlerLoader(IHandlerLoader):
    name = "log_mysql"

    @classmethod
    def start(cls, config=None):
        return logsqlhandler("*", config=config)


class logsqlhandler(ihandler):
    def __init__(self, path, config=None):
        logger.debug("%s ready!" % (self.__class__.__name__))
        self.path = path
        self.database = config.get("database", "")
        self.user = config.get("user", "")
        self.password = config.get("password", "")
        self.host = config.get("host", "")
        self.port = config.get("port", "")
        self.geoipdb_city_path = config.get("geoipdb").get("geoipdb_city_path", "")
        self.geoipdb_asn_path = config.get("geoipdb").get("geoipdb_asn_path", "")
        self.vtapikey = config.get("virustotal").get("apikey", "")
        print("!!!!!!!!!database!!!!!!!!", self.database)
        print("!!!!!!!!!user!!!!!!!!", self.user)
        print("!!!!!!!!!password!!!!!!!!", self.password)
        print("!!!!!!!!!host!!!!!!!!", self.host)
        print("!!!!!!!!!port!!!!!!!!", self.port)
        print("!!!!!!!!!geoipdb!!!!!!!!", config.get("geoipdb"))
        print("!!!!!!!!!vtapikey!!!!!!!!", self.vtapikey)

    def start(self):
        ihandler.__init__(self, self.path)
        # mapping socket -> attackid
        self.attacks = {}

        self.pending = {}

        try:
            self.dbh = MySQLdb.connect(host=self.host, user=self.user, passwd=self.password, db=self.database, port=int(self.port), charset="utf8", use_unicode=True)
        except:
            print("Unable to connect the database")

        self.cursor = self.dbh.cursor()

        update = False

        self.cursor.execute("""CREATE TABLE IF NOT EXISTS 
        connections (
                connection INTEGER NOT NULL AUTO_INCREMENT,
                connection_type VARCHAR(15),
                connection_transport TEXT,
                connection_protocol TEXT,
                connection_timestamp INTEGER,
                connection_root INTEGER,
                connection_parent INTEGER,
                local_host VARCHAR(15),
                local_port INTEGER,
                remote_host VARCHAR(15),
                remote_hostname TEXT,
                remote_port INTEGER,
                country_name VARCHAR(45) DEFAULT '',
                country_iso_code varchar(2) DEFAULT '',
                city_name VARCHAR(128) DEFAULT '',
                org VARCHAR(128) DEFAULT '',
                org_asn INTEGER,
                connection_datetime DATETIME,
                PRIMARY KEY (connection)
        )""")

        self.cursor.execute("""DROP TRIGGER IF EXISTS connections_INSERT_update_connection_root_trg""")
        self.cursor.execute("""CREATE TRIGGER connections_INSERT_update_connection_root_trg
            BEFORE INSERT ON connections
            FOR EACH ROW
                BEGIN
                    SET @max_id = (SELECT MAX(connection) FROM connections);
                    IF @max_id is NULL THEN
                        SET NEW.connection_root = 1;
                    ELSE     
                        SET NEW.connection_root = @max_id + 1;
                    END IF;
                END;
            """)
        
        for idx in ["type","timestamp","root","parent"]:
            if if_not_exist_index(self, "connections", "connections_%s_idx"%idx):
                self.cursor.execute("""CREATE INDEX connections_%s_idx
                ON connections (connection_%s)""" % (idx, idx))

        for idx in ["local_host","local_port","remote_host"]:
            if if_not_exist_index(self, "connections", "connections_%s_idx"%idx):
                self.cursor.execute("""CREATE INDEX connections_%s_idx
                ON connections (%s)""" % (idx, idx))


#         self.cursor.execute("""CREATE TABLE IF NOT EXISTS
#            bistreams (
#                bistream INTEGER NOT NULL AUTO_INCREMENT,
#                connection INTEGER,
#                bistream_data TEXT,
#         PRIMARY KEY (bistream)
#            )""")
#
#        self.cursor.execute("""CREATE TABLE IF NOT EXISTS
#            smbs (
#                smb NOT NULL AUTO_INCREMENT,
#                connection INTEGER,
#                smb_direction TEXT,
#                smb_action TEXT,
#                CONSTRAINT smb_connection_fkey FOREIGN KEY (connection) REFERENCES connections (connection),
#         PRIMARY KEY (smb)
#            )""")

        self.cursor.execute("""CREATE TABLE IF NOT EXISTS 
            dcerpcbinds (
                dcerpcbind INTEGER NOT NULL AUTO_INCREMENT,
                connection INTEGER,
                dcerpcbind_uuid VARCHAR(36),
                dcerpcbind_transfersyntax VARCHAR(36),
                PRIMARY KEY (dcerpcbind)
                -- CONSTRAINT dcerpcs_connection_fkey FOREIGN KEY (connection) REFERENCES connections (connection)
            )""")

        for idx in ["uuid","transfersyntax"]:
            if if_not_exist_index(self, "dcerpcbinds", "dcerpcbinds_%s_idx"%idx):
                self.cursor.execute("""CREATE INDEX dcerpcbinds_%s_idx
                ON dcerpcbinds (dcerpcbind_%s)""" % (idx, idx))

        self.cursor.execute("""CREATE TABLE IF NOT EXISTS 
            dcerpcrequests (
                dcerpcrequest INTEGER NOT NULL AUTO_INCREMENT,
                connection INTEGER,
                dcerpcrequest_uuid VARCHAR(36),
                dcerpcrequest_opnum INTEGER,
                PRIMARY KEY (dcerpcrequest)
                -- CONSTRAINT dcerpcs_connection_fkey FOREIGN KEY (connection) REFERENCES connections (connection)
            )""")

        for idx in ["uuid","opnum"]:
            if if_not_exist_index(self, "dcerpcrequests", "dcerpcrequests_%s_idx"%idx):
                self.cursor.execute("""CREATE INDEX dcerpcrequests_%s_idx
                ON dcerpcrequests (dcerpcrequest_%s)""" % (idx, idx))


        self.cursor.execute("""CREATE TABLE IF NOT EXISTS
            dcerpcservices (
                dcerpcservice INTEGER NOT NULL AUTO_INCREMENT,
                dcerpcservice_uuid VARCHAR(36),
                dcerpcservice_name TEXT,
                CONSTRAINT dcerpcservice_uuid_uniq UNIQUE (dcerpcservice_uuid),
                PRIMARY KEY (dcerpcservice)
            )""")

        from uuid import UUID
        from dionaea.smb import rpcservices
        import inspect
        services = inspect.getmembers(rpcservices, inspect.isclass)
        for name, servicecls in services:
            if not name == 'RPCService' and issubclass(servicecls, rpcservices.RPCService):
                try:
                    self.cursor.execute("INSERT INTO dcerpcservices (dcerpcservice_name, dcerpcservice_uuid) VALUES (%s,%s)",
                                        (name, str(UUID(hex=servicecls.uuid))) )
                except Exception as e:
#                    print("dcerpcservice %s existed %s " % (servicecls.uuid, e) )
                    pass

        #self.dbh.commit()

        logger.info("Getting RPC Services")
        r = self.cursor.execute("SELECT * FROM dcerpcservices")
#        print(r)
        names = [self.cursor.description[x][0] for x in range(len(self.cursor.description))]
        r = [ dict(zip(names, i)) for i in self.cursor]
#        print(r)
        r = dict([(UUID(i['dcerpcservice_uuid']).hex,i['dcerpcservice'])
                  for i in r])
#        print(r)


        self.cursor.execute("""CREATE TABLE IF NOT EXISTS
            dcerpcserviceops (
                dcerpcserviceop INTEGER NOT NULL AUTO_INCREMENT,
                dcerpcservice INTEGER,
                dcerpcserviceop_opnum INTEGER,
                dcerpcserviceop_name TEXT,
                dcerpcserviceop_vuln TEXT,
                CONSTRAINT dcerpcop_service_opnum_uniq UNIQUE (dcerpcservice, dcerpcserviceop_opnum),
                PRIMARY KEY (dcerpcserviceop)
            )""")

        logger.info("Setting RPC ServiceOps")
        for name, servicecls in services:
            if not name == 'RPCService' and issubclass(servicecls, rpcservices.RPCService):
                for opnum in servicecls.ops:
                    op = servicecls.ops[opnum]
                    uuid = servicecls.uuid
                    vuln = ''
                    dcerpcservice = r[uuid]
                    if opnum in servicecls.vulns:
                        vuln = servicecls.vulns[opnum]
                    try:
                        self.cursor.execute("INSERT INTO dcerpcserviceops (dcerpcservice, dcerpcserviceop_opnum, dcerpcserviceop_name, dcerpcserviceop_vuln) VALUES (%s,%s,%s,%s)",
                             (dcerpcservice, opnum, op, vuln))
                    except:
#                        print("%s %s %s %s %s existed" % (dcerpcservice, uuid, name, op, vuln))
                        pass

        #self.dbh.commit()

        # NetPathCompare was called NetCompare in dcerpcserviceops
        try:
            logger.debug("Trying to update table: dcerpcserviceops")
            self.cursor.execute(
                """SELECT * FROM dcerpcserviceops WHERE dcerpcserviceop_name = 'NetCompare'""")
            x = self.cursor.fetchall()
            if len(x) > 0:
                self.cursor.execute(
                    """UPDATE dcerpcserviceops SET dcerpcserviceop_name = 'NetPathCompare' WHERE dcerpcserviceop_name = 'NetCompare'""")
                logger.debug("... done")
            else:
                logger.info("... not required")
        except Exception as e:
            print(e)
            logger.info("... not required")

        self.cursor.execute("""CREATE TABLE IF NOT EXISTS
            emu_profiles (
                emu_profile INTEGER NOT NULL AUTO_INCREMENT,
                connection INTEGER,
                emu_profile_json TEXT,
                PRIMARY KEY (emu_profile) 
                -- CONSTRAINT emu_profiles_connection_fkey FOREIGN KEY (connection) REFERENCES connections (connection)
            )""")

        # self.dbh.commit()

        self.cursor.execute("""CREATE TABLE IF NOT EXISTS 
            emu_services (
                emu_serivce INTEGER NOT NULL AUTO_INCREMENT,
                connection INTEGER,
                emu_service_url TEXT,
                PRIMARY KEY (emu_serivce)
                -- CONSTRAINT emu_services_connection_fkey FOREIGN KEY (connection) REFERENCES connections (connection)
            )""")

        self.cursor.execute("""CREATE TABLE IF NOT EXISTS 
            offers (
                offer INTEGER NOT NULL AUTO_INCREMENT,
                connection INTEGER,
                offer_url VARCHAR(2000),
                PRIMARY KEY (offer)
                -- CONSTRAINT offers_connection_fkey FOREIGN KEY (connection) REFERENCES connections (connection)
            )""")

        if if_not_exist_index(self, "offers", "offers_url_idx"):
            self.cursor.execute(
                """CREATE INDEX offers_url_idx ON offers (offer_url)""")

        self.cursor.execute("""CREATE TABLE IF NOT EXISTS
            downloads (
                download INTEGER NOT NULL AUTO_INCREMENT,
                connection INTEGER,
                download_url VARCHAR(2000),
                download_md5_hash VARCHAR(32),
                connection_timestamp INTEGER,
                filesize INTEGER,
                connection_datetime DATETIME,
                PRIMARY KEY (download)
                -- CONSTRAINT downloads_connection_fkey FOREIGN KEY (connection) REFERENCES connections (connection)
            )""")

        for idx in ["url", "md5_hash"]:
            if if_not_exist_index(self, "downloads", "downloads_%s_idx"%idx):
                self.cursor.execute("""CREATE INDEX downloads_%s_idx
                ON downloads (download_%s)""" % (idx, idx))


        self.cursor.execute("""CREATE TABLE IF NOT EXISTS
            resolves (
                resolve INTEGER NOT NULL AUTO_INCREMENT,
                connection INTEGER,
                resolve_hostname TEXT,
                resolve_type TEXT,
                resolve_result TEXT,
                PRIMARY KEY (resolve)
            )""")

        self.cursor.execute("""CREATE TABLE IF NOT EXISTS
            p0fs (
                p0f INTEGER NOT NULL AUTO_INCREMENT,
                connection INTEGER,
                p0f_genre VARCHAR(100),
                p0f_link TEXT,
                p0f_detail VARCHAR(256),
                p0f_uptime INTEGER,
                p0f_tos TEXT,
                p0f_dist INTEGER,
                p0f_nat INTEGER,
                p0f_fw INTEGER,
                PRIMARY KEY (p0f)
                -- CONSTRAINT p0fs_connection_fkey FOREIGN KEY (connection) REFERENCES connections (connection)
            )""")

        for idx in ["genre","detail","uptime"]:
            if if_not_exist_index(self, "p0fs", "p0fs_%s_idx"%idx):
                self.cursor.execute("""CREATE INDEX p0fs_%s_idx
                ON p0fs (p0f_%s)""" % (idx, idx))

        self.cursor.execute("""CREATE TABLE IF NOT EXISTS
            logins (
                login INTEGER NOT NULL AUTO_INCREMENT,
                connection INTEGER,
                login_username VARCHAR(100),
                login_password VARCHAR(100),
                PRIMARY KEY (login)
                -- CONSTRAINT logins_connection_fkey FOREIGN KEY (connection) REFERENCES connections (connection)
            )""")

        for idx in ["username","password"]:
            if if_not_exist_index(self, "logins", "logins_%s_idx"%idx):
                self.cursor.execute("""CREATE INDEX logins_%s_idx
                ON logins (login_%s)""" % (idx, idx))

        self.cursor.execute("""CREATE TABLE IF NOT EXISTS
            mssql_fingerprints (
                mssql_fingerprint INTEGER NOT NULL AUTO_INCREMENT,
                connection INTEGER,
                mssql_fingerprint_hostname VARCHAR(512),
                mssql_fingerprint_appname VARCHAR(512),
                mssql_fingerprint_cltintname VARCHAR(512),
                PRIMARY KEY (mssql_fingerprint)
                -- CONSTRAINT mssql_fingerprints_connection_fkey FOREIGN KEY (connection) REFERENCES connections (connection)
            )""")

        for idx in ["hostname","appname","cltintname"]:
            if if_not_exist_index(self, "mssql_fingerprints", "mssql_fingerprints_%s_idx"%idx):
                self.cursor.execute("""CREATE INDEX mssql_fingerprints_%s_idx
                ON mssql_fingerprints (mssql_fingerprint_%s)""" % (idx, idx))

        self.cursor.execute("""CREATE TABLE IF NOT EXISTS
            mssql_commands (
                mssql_command INTEGER NOT NULL AUTO_INCREMENT,
                connection INTEGER,
                mssql_command_status VARCHAR(512),
                mssql_command_cmd TEXT,
                PRIMARY KEY (mssql_command)
                -- CONSTRAINT mssql_commands_connection_fkey FOREIGN KEY (connection) REFERENCES connections (connection)
            )""")

        for idx in ["status"]:
            if if_not_exist_index(self, "mssql_commands", "mssql_commands_%s_idx"%idx):
                self.cursor.execute("""CREATE INDEX mssql_commands_%s_idx
                ON mssql_commands (mssql_command_%s)""" % (idx, idx))



        self.cursor.execute("""CREATE TABLE IF NOT EXISTS virustotals (
                virustotal INTEGER NOT NULL AUTO_INCREMENT,
                virustotal_md5_hash VARCHAR(32) NOT NULL,
                virustotal_timestamp INTEGER NOT NULL,
                virustotal_permalink TEXT NOT NULL,
                PRIMARY KEY (virustotal)
            )""")

        for idx in ["md5_hash"]:
            if if_not_exist_index(self, "virustotals", "virustotals_%s_idx"%idx):
                self.cursor.execute("""CREATE INDEX virustotals_%s_idx
                ON virustotals (virustotal_%s)""" % (idx, idx))

        self.cursor.execute("""CREATE TABLE IF NOT EXISTS virustotalscans (
            virustotalscan INTEGER NOT NULL AUTO_INCREMENT,
            virustotal INTEGER NOT NULL,
            virustotalscan_scanner VARCHAR(256) NOT NULL,
            virustotalscan_result VARCHAR(512),
            PRIMARY KEY (virustotalscan)
        )""")

        for idx in ["scanner","result"]:
            if if_not_exist_index(self, "virustotalscans", "virustotalscans_%s_idx"%idx):
                self.cursor.execute("""CREATE INDEX virustotalscans_%s_idx
                ON virustotalscans (virustotalscan_%s)""" % (idx, idx))

        if if_not_exist_index(self, "virustotalscans", "virustotalscans_virustotal_idx"):
            self.cursor.execute("""CREATE INDEX virustotalscans_virustotal_idx
                ON virustotalscans (virustotal)""")

        self.cursor.execute("""CREATE TABLE IF NOT EXISTS
            mysql_commands (
                mysql_command INTEGER NOT NULL AUTO_INCREMENT,
                connection INTEGER,
                mysql_command_cmd NUMERIC NOT NULL,
                PRIMARY KEY (mysql_command)
                -- CONSTRAINT mysql_commands_connection_fkey FOREIGN KEY (connection) REFERENCES connections (connection)
            )""")

        self.cursor.execute("""CREATE TABLE IF NOT EXISTS
            mysql_command_args (
                mysql_command_arg INTEGER NOT NULL AUTO_INCREMENT,
                mysql_command INTEGER,
                mysql_command_arg_index NUMERIC NOT NULL,
                mysql_command_arg_data TEXT NOT NULL,
                PRIMARY KEY (mysql_command_arg)
                -- CONSTRAINT mysql_commands_connection_fkey FOREIGN KEY (connection) REFERENCES connections (connection)
            )""")

        for idx in ["command"]:
            if if_not_exist_index(self, "mysql_command_args", "mysql_command_args_%s_idx"%idx):
                self.cursor.execute("""CREATE INDEX mysql_command_args_%s_idx
                ON mysql_command_args (mysql_%s)""" % (idx, idx))

        self.cursor.execute("""CREATE TABLE IF NOT EXISTS
            mysql_command_ops (
                mysql_command_op INTEGER NOT NULL AUTO_INCREMENT,
                mysql_command_cmd INTEGER NOT NULL,
                mysql_command_op_name TEXT NOT NULL,
                CONSTRAINT mysql_command_cmd_uniq UNIQUE (mysql_command_cmd),
                PRIMARY KEY (mysql_command_op)
            )""")

        from dionaea.mysql.include.packets import MySQL_Commands
        logger.info("Setting MySQL Command Ops")
        for num,name in MySQL_Commands.items():
            try:
                self.cursor.execute("INSERT INTO mysql_command_ops (mysql_command_cmd, mysql_command_op_name) VALUES (%s,%s)",
                                    (num, name))
            except:
                pass

        self.cursor.execute("""CREATE TABLE IF NOT EXISTS
            sip_commands (
                sip_command INTEGER NOT NULL AUTO_INCREMENT,
                connection INTEGER,
                sip_command_method TEXT,
                sip_command_call_id TEXT,
                sip_command_user_agent TEXT,
                sip_command_allow INTEGER,
                PRIMARY KEY (sip_command)
            -- CONSTRAINT sip_commands_connection_fkey FOREIGN KEY (connection) REFERENCES connections (connection)
        )""")

        self.cursor.execute("""CREATE TABLE IF NOT EXISTS
            sip_addrs (
                sip_addr INTEGER NOT NULL AUTO_INCREMENT,
                sip_command INTEGER,
                sip_addr_type TEXT,
                sip_addr_display_name TEXT,
                sip_addr_uri_scheme TEXT,
                sip_addr_uri_user TEXT,
                sip_addr_uri_password TEXT,
                sip_addr_uri_host TEXT,
                sip_addr_uri_port TEXT,
                PRIMARY KEY (sip_addr)
                -- CONSTRAINT sip_addrs_command_fkey FOREIGN KEY (sip_command) REFERENCES sip_commands (sip_command)
            )""")

        self.cursor.execute("""CREATE TABLE IF NOT EXISTS
            sip_vias (
                sip_via INTEGER NOT NULL AUTO_INCREMENT,
                sip_command INTEGER,
                sip_via_protocol TEXT,
                sip_via_address TEXT,
                sip_via_port TEXT,
                PRIMARY KEY (sip_via)
                -- CONSTRAINT sip_vias_command_fkey FOREIGN KEY (sip_command) REFERENCES sip_commands (sip_command)
            )""")

        self.cursor.execute("""CREATE TABLE IF NOT EXISTS
            sip_sdp_origins (
                sip_sdp_origin INTEGER NOT NULL AUTO_INCREMENT,
                sip_command INTEGER,
                sip_sdp_origin_username TEXT,
                sip_sdp_origin_sess_id TEXT,
                sip_sdp_origin_sess_version TEXT,
                sip_sdp_origin_nettype TEXT,
                sip_sdp_origin_addrtype TEXT,
                sip_sdp_origin_unicast_address TEXT,
                PRIMARY KEY (sip_sdp_origin)
                -- CONSTRAINT sip_sdp_origins_fkey FOREIGN KEY (sip_command) REFERENCES sip_commands (sip_command)
            )""")

        self.cursor.execute("""CREATE TABLE IF NOT EXISTS
            sip_sdp_connectiondatas (
                sip_sdp_connectiondata INTEGER NOT NULL AUTO_INCREMENT,
                sip_command INTEGER,
                sip_sdp_connectiondata_nettype TEXT,
                sip_sdp_connectiondata_addrtype TEXT,
                sip_sdp_connectiondata_connection_address TEXT,
                sip_sdp_connectiondata_ttl TEXT,
                sip_sdp_connectiondata_number_of_addresses TEXT,
                PRIMARY KEY (sip_sdp_connectiondata)
                -- CONSTRAINT sip_sdp_connectiondatas_fkey FOREIGN KEY (sip_command) REFERENCES sip_commands (sip_command)
            )""")

        self.cursor.execute("""CREATE TABLE IF NOT EXISTS
            sip_sdp_medias (
                sip_sdp_media INTEGER NOT NULL AUTO_INCREMENT,
                sip_command INTEGER,
                sip_sdp_media_media TEXT,
                sip_sdp_media_port TEXT,
                sip_sdp_media_number_of_ports TEXT,
                sip_sdp_media_proto TEXT,
                PRIMARY KEY (sip_sdp_media)
--                sip_sdp_media_fmt,
--                sip_sdp_media_attributes      
                -- CONSTRAINT sip_sdp_medias_fkey FOREIGN KEY (sip_command) REFERENCES sip_commands (sip_command)
            )""")

#        self.cursor.execute("""CREATE TABLE IF NOT EXISTS
#            httpheaders (
#                httpheader INTEGER NOT NULL AUTO_INCREMENT,
#                connection INTEGER,
#                http_headerkey TEXT,
#                http_headervalue TEXT,
#               PRIMARY KEY (httpheader)
#                -- CONSTRAINT httpheaders_connection_fkey FOREIGN KEY (connection) REFERENCES connections (connection)
#            )""")
#
#        for idx in ["headerkey","headervalue"]:
#            self.cursor.execute("""CREATE INDEX httpheaders_%s_idx 
#            ON httpheaders (httpheader_%s)""" % (idx, idx))

        self.cursor.execute("""CREATE TABLE IF NOT EXISTS
            mqtt_fingerprints (
                mqtt_fingerprint INTEGER NOT NULL AUTO_INCREMENT,
                connection INTEGER,
                mqtt_fingerprint_clientid VARCHAR(512),
                mqtt_fingerprint_willtopic VARCHAR(512),
                mqtt_fingerprint_willmessage VARCHAR(512),
                mqtt_fingerprint_username VARCHAR(100),
                mqtt_fingerprint_password VARCHAR(100),
                PRIMARY KEY (mqtt_fingerprint)
                -- CONSTRAINT mqtt_fingerprints_connection_fkey FOREIGN KEY (connection) REFERENCES connections (connection)
            )""")

        for idx in ["clientid","willtopic","willmessage", "username", "password"]:
            if if_not_exist_index(self, "mqtt_fingerprints", "mqtt_fingerprints_%s_idx"%idx):
                self.cursor.execute("""CREATE INDEX mqtt_fingerprints_%s_idx 
                ON mqtt_fingerprints (mqtt_fingerprint_%s)""" % (idx, idx))

        self.cursor.execute("""CREATE TABLE IF NOT EXISTS
            mqtt_publish_commands (
                mqtt_publish_command INTEGER NOT NULL AUTO_INCREMENT,
                connection INTEGER,
                mqtt_publish_command_topic VARCHAR(512),
                mqtt_publish_command_message VARCHAR(512),
                PRIMARY KEY (mqtt_publish_command)
                -- CONSTRAINT mqtt_publish_commands_connection_fkey FOREIGN KEY (connection) REFERENCES connections (connection)
            )""")

        for idx in ["topic", "message"]:
            if if_not_exist_index(self, "mqtt_publish_commands", "mqtt_publish_commands_%s_idx"%idx):
                self.cursor.execute("""CREATE INDEX mqtt_publish_commands_%s_idx 
                ON mqtt_publish_commands (mqtt_publish_command_%s)""" % (idx, idx))

        self.cursor.execute("""CREATE TABLE IF NOT EXISTS
            mqtt_subscribe_commands (
                mqtt_subscribe_command INTEGER NOT NULL AUTO_INCREMENT,
                connection INTEGER,
                mqtt_subscribe_command_messageid VARCHAR(512),
                mqtt_subscribe_command_topic VARCHAR(512),
                PRIMARY KEY (mqtt_subscribe_command)
                -- CONSTRAINT mqtt_subscribe_commands_connection_fkey FOREIGN KEY (connection) REFERENCES connections (connection)
            )""")

        for idx in ["messageid", "topic"]:
            if if_not_exist_index(self, "mqtt_subscribe_commands", "mqtt_subscribe_commands_%s_idx"%idx):
                self.cursor.execute("""CREATE INDEX mqtt_subscribe_commands_%s_idx 
                ON mqtt_subscribe_commands (mqtt_subscribe_command_%s)""" % (idx, idx))

        # connection index for all
        for idx in ["dcerpcbinds", "dcerpcrequests", "emu_profiles", "emu_services", "offers", "downloads", "p0fs", "logins", "mssql_fingerprints", "mssql_commands","mysql_commands","sip_commands", "mqtt_fingerprints", "mqtt_publish_commands", "mqtt_subscribe_commands"]:
            if if_not_exist_index(self, "%s"%idx, "%s_connection_idx"%idx):
                self.cursor.execute(
                    """CREATE INDEX %s_connection_idx    ON %s (connection)""" % (idx, idx)
                )


        self.dbh.commit()


        # updates, database schema corrections for old versions

        # svn rev 2143 removed the table dcerpcs
        # and created the table dcerpcrequests
        #
        # copy the data to the new table dcerpcrequests
        # drop the old table
        try:
            logger.debug("Updating Table dcerpcs")
            self.cursor.execute("""INSERT INTO
                                    dcerpcrequests (connection, dcerpcrequest_uuid, dcerpcrequest_opnum)
                                SELECT
                                    connection, dcerpc_uuid, dcerpc_opnum
                                FROM
                                    dcerpcs""")
            self.cursor.execute("""DROP TABLE dcerpcs""")
            logger.debug("... done")
        except Exception as e:
            #            print(e)
            logger.debug("... not required")

        try:
            self.reader_city = geoip2.database.Reader(self.geoipdb_city_path)
        except:
            logger.warning("Failed to open GeoIP database %s", self.geoipdb_city_path)

        try:
            self.reader_asn = geoip2.database.Reader(self.geoipdb_asn_path)
        except:
            logger.warning("Failed to open GeoIP database %s", self.geoipdb_asn_path)

    def __del__(self):
        logger.info("Closing mysql handle")
        self.cursor.close()
        self.cursor = None
        self.dbh.close()
        self.dbh = None
        if self.reader_city is not None:
           self.reader_city.close()
        if self.reader_asn is not None:
           self.reader_asn.close()

    def _handle_credentials(self, icd):
        """
        Insert credentials into the logins table.

        :param icd: Incident
        """
        con = icd.con
        if con in self.attacks:
            attack_id = self.attacks[con][1]
            try:
                self.cursor.execute(
                    "INSERT INTO logins (connection, login_username, login_password) VALUES (%s,%s,%s)",
                    (attack_id, icd.username, icd.password)
                )
            except Exception as e:
                print(e)

            self.dbh.commit()

    def handle_incident(self, icd):
        #        print("unknown")
        pass

    def connection_insert(self, icd, connection_type):

        con=icd.con

        try:
            response_city = self.reader_city.city(con.remote.host)
            city = response_city.city.name
            if city is None:
                city = ""
            country = response_city.country.name
            if country is None:
                country = ''
                country_code = ''
            else:            
                country_code = response_city.country.iso_code
        except:
            city = ""
            country = ""
            country_code = ''
        
        try:
            response_asn = self.reader_asn.asn(con.remote.host)
            if response_asn.autonomous_system_organization is not None:
                org = response_asn.autonomous_system_organization.encode('utf8')
            else:
                org = ""
                
            if response_asn.autonomous_system_number is not None:
                asn_num = response_asn.autonomous_system_number
            else:
                asn_num = 0
        except:
            org = ""
            asn_num = 0    

        print ("!!!!!!!!!!", city, country, country_code, org, asn_num, con.remote.host)

        t = time.time()
        dt = datetime.datetime.fromtimestamp(t)
        try:        
            r = self.cursor.execute("INSERT INTO connections (connection_timestamp, connection_type, connection_transport, connection_protocol, local_host, local_port, remote_host, remote_hostname, remote_port, country_name, country_iso_code, city_name, org, org_asn, connection_datetime) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                                    (t, connection_type, con.transport, con.protocol, con.local.host, con.local.port, con.remote.host, con.remote.hostname, con.remote.port, country, country_code, city, org, asn_num, dt) )
        except Exception as e:
            print(e)        
        attackid = self.cursor.lastrowid
        self.attacks[con] = (attackid, attackid, t, dt)
        self.dbh.commit()

        # maybe this was a early connection?
        if con in self.pending:
            # the connection was linked before we knew it
            # that means we have to
            # - update the connection_root and connection_parent for all connections which had the pending
            # - update the connection_root for all connections which had the 'childid' as connection_root
            for i in self.pending[con]:
                print("%s %s %s" % (attackid, attackid, i))
            try:                
                self.cursor.execute("UPDATE connections SET connection_root = %s, connection_parent = %s WHERE connection = %s",
                                    (attackid, attackid, i ) )
                self.cursor.execute("UPDATE connections SET connection_root = %s WHERE connection_root = %s",
                                    (attackid, i ) )
            except Exception as e:
                print(e)
        self.dbh.commit()

        return attackid


    def handle_incident_dionaea_connection_tcp_listen(self, icd):
        attackid = self.connection_insert( icd, 'listen')
        con=icd.con
        logger.info("listen connection on %s:%i (id=%i)" %
                    (con.remote.host, con.remote.port, attackid))

    def handle_incident_dionaea_connection_tls_listen(self, icd):
        attackid = self.connection_insert( icd, 'listen')
        con=icd.con
        logger.info("listen connection on %s:%i (id=%i)" %
                    (con.remote.host, con.remote.port, attackid))

    def handle_incident_dionaea_connection_tcp_connect(self, icd):
        attackid = self.connection_insert( icd, 'connect')
        con=icd.con
        logger.info("connect connection to %s/%s:%i from %s:%i (id=%i)" %
                    (con.remote.host, con.remote.hostname, con.remote.port, con.local.host, con.local.port, attackid))

    def handle_incident_dionaea_connection_tls_connect(self, icd):
        attackid = self.connection_insert( icd, 'connect')
        con=icd.con
        logger.info("connect connection to %s/%s:%i from %s:%i (id=%i)" %
                    (con.remote.host, con.remote.hostname, con.remote.port, con.local.host, con.local.port, attackid))

    def handle_incident_dionaea_connection_udp_connect(self, icd):
        attackid = self.connection_insert( icd, 'connect')
        con=icd.con
        logger.info("connect connection to %s/%s:%i from %s:%i (id=%i)" %
                    (con.remote.host, con.remote.hostname, con.remote.port, con.local.host, con.local.port, attackid))

    def handle_incident_dionaea_connection_tcp_accept(self, icd):
        attackid = self.connection_insert( icd, 'accept')
        con=icd.con
        logger.info("accepted connection from %s:%i to %s:%i (id=%i)" %
                    (con.remote.host, con.remote.port, con.local.host, con.local.port, attackid))

    def handle_incident_dionaea_connection_tls_accept(self, icd):
        attackid = self.connection_insert( icd, 'accept')
        con=icd.con
        logger.info("accepted connection from %s:%i to %s:%i (id=%i)" %
                    (con.remote.host, con.remote.port, con.local.host, con.local.port, attackid))


    def handle_incident_dionaea_connection_tcp_reject(self, icd):
        attackid = self.connection_insert(icd, 'reject')
        con=icd.con
        logger.info("reject connection from %s:%i to %s:%i (id=%i)" %
                    (con.remote.host, con.remote.port, con.local.host, con.local.port, attackid))

    def handle_incident_dionaea_connection_tcp_pending(self, icd):
        attackid = self.connection_insert(icd, 'pending')
        con=icd.con
        logger.info("pending connection from %s:%i to %s:%i (id=%i)" %
                    (con.remote.host, con.remote.port, con.local.host, con.local.port, attackid))

    def handle_incident_dionaea_connection_link_early(self, icd):
        # if we have to link a connection with a connection we do not know yet,
        # we store the unknown connection in self.pending and associate the
        # childs id with it
        if icd.parent not in self.attacks:
            if icd.parent not in self.pending:
                self.pending[icd.parent] = {self.attacks[icd.child][1]: True}
            else:
                if icd.child not in self.pending[icd.parent]:
                    self.pending[icd.parent][self.attacks[icd.child][1]] = True

    def handle_incident_dionaea_connection_link(self, icd):
        if icd.parent in self.attacks:
            logger.info("parent ids %s" % str(self.attacks[icd.parent]))
            parentroot, parentid = self.attacks[icd.parent]
            if icd.child in self.attacks:
                logger.info("child had ids %s" % str(self.attacks[icd.child]))
                childroot, childid = self.attacks[icd.child]
            else:
                childid = parentid
            self.attacks[icd.child] = (parentroot, childid, 0)
            logger.info("child has ids %s" % str(self.attacks[icd.child]))
            logger.info("child %i parent %i root %i" %
                        (childid, parentid, parentroot) )
            try:            
                r = self.cursor.execute("UPDATE connections SET connection_root = %s, connection_parent = %s WHERE connection = %s",
                                    (parentroot, parentid, childid) )
            except Exception as e:
                print(e)
            self.dbh.commit()

        if icd.child in self.pending:
            # if the new accepted connection was pending
            # assign the connection_root to all connections which have been
            # waiting for this connection
            parentroot, parentid = self.attacks[icd.parent]
            if icd.child in self.attacks:
                childroot, childid = self.attacks[icd.child]
            else:
                childid = parentid
            try:
                self.cursor.execute("UPDATE connections SET connection_root = %s WHERE connection_root = %s",
                                (parentroot, childid) )
            except Exception as e:
                print(e)
            self.dbh.commit()

    def handle_incident_dionaea_connection_free(self, icd):
        con=icd.con
        if con in self.attacks:
            attackid = self.attacks[con][1]
            del self.attacks[con]
            logger.info("attackid %i is done" % attackid)
        else:
            logger.warn("no attackid for %s:%s" %
                        (con.local.host, con.local.port) )
        if con in self.pending:
            del self.pending[con]


    def handle_incident_dionaea_module_emu_profile(self, icd):
        con = icd.con
        if con not in self.attacks:
            return
        attackid = self.attacks[con][1]
        logger.info("emu profile for attackid %i" % attackid)
        try:
            self.cursor.execute("INSERT INTO emu_profiles (connection, emu_profile_json) VALUES (%s,%s)",
                                (attackid, icd.profile) )
        except Exception as e:
            print(e)        
        self.dbh.commit()


    def handle_incident_dionaea_download_offer(self, icd):
        con=icd.con
        if con not in self.attacks:
            return
        attackid = self.attacks[con][1]
        logger.info("offer for attackid %i" % attackid)
        try:
            self.cursor.execute("INSERT INTO offers (connection, offer_url) VALUES (%s,%s)",
                            (attackid, icd.url) )
        except Exception as e:
            print(e)
        self.dbh.commit()

    def handle_incident_dionaea_download_complete_hash(self, icd):
        con=icd.con
        if con not in self.attacks:
            return
        attackid = self.attacks[con][1]
        time = self.attacks[con][2]
        dt = self.attacks[con][3]
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!1", self.attacks[con])
        logger.info("complete for attackid %i" % attackid)
        print("!!!!!!!!!!!!!!!!!!!1", icd.file_size)
        try:
            self.cursor.execute("INSERT INTO downloads (connection, download_url, download_md5_hash, connection_timestamp, filesize, connection_datetime) VALUES (%s,%s,%s,%s,%s,%s)",
                            (attackid, icd.url, icd.md5hash, time, icd.file_size, dt))
        except Exception as e:
            print(e)
        self.dbh.commit()

        self.handle_incident_dionaea_modules_python_virustotal_report(icd)


    def handle_incident_dionaea_service_shell_listen(self, icd):
        con=icd.con
        if con not in self.attacks:
            return
        attackid = self.attacks[con][1]
        logger.info("listen shell for attackid %i" % attackid)
        try:        
            self.cursor.execute("INSERT INTO emu_services (connection, emu_service_url) VALUES (%s,%s)",
                                (attackid, "bindshell://"+str(icd.port)) )
        except Exception as e:
            print(e)
        self.dbh.commit()

    def handle_incident_dionaea_service_shell_connect(self, icd):
        con=icd.con
        if con not in self.attacks:
            return
        attackid = self.attacks[con][1]
        logger.info("connect shell for attackid %i" % attackid)
        try:        
            self.cursor.execute("INSERT INTO emu_services (connection, emu_service_url) VALUES (%s,%s)",
                                (attackid, "connectbackshell://"+str(icd.host)+":"+str(icd.port)) )
        except Exception as e:
            print(e)
            
        self.dbh.commit()

    def handle_incident_dionaea_modules_python_p0f(self, icd):
        con=icd.con
        if con in self.attacks:
            attackid = self.attacks[con][1]
        try:    
            self.cursor.execute("INSERT INTO p0fs (connection, p0f_genre, p0f_link, p0f_detail, p0f_uptime, p0f_tos, p0f_dist, p0f_nat, p0f_fw) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                                ( attackid, icd.genre, icd.link, icd.detail, icd.uptime, icd.tos, icd.dist, icd.nat, icd.fw))
        except Exception as e:
            print(e)

        self.dbh.commit()

    def handle_incident_dionaea_modules_python_ftp_login(self, icd):
        self._handle_credentials(icd)

    def handle_incident_dionaea_modules_python_smb_dcerpc_request(self, icd):
        con=icd.con
        if con in self.attacks:
            attackid = self.attacks[con][1]
        try:            
            self.cursor.execute("INSERT INTO dcerpcrequests (connection, dcerpcrequest_uuid, dcerpcrequest_opnum) VALUES (%s,%s,%s)",
                                (attackid, icd.uuid, icd.opnum))
        except Exception as e:
            print(e)

        self.dbh.commit()

    def handle_incident_dionaea_modules_python_smb_dcerpc_bind(self, icd):
        con=icd.con
        if con in self.attacks:
            attackid = self.attacks[con][1]
        try:            
            self.cursor.execute("INSERT INTO dcerpcbinds (connection, dcerpcbind_uuid, dcerpcbind_transfersyntax) VALUES (%s,%s,%s)",
                                (attackid, icd.uuid, icd.transfersyntax))
        except Exception as e:
            print(e)

        self.dbh.commit()

    def handle_incident_dionaea_modules_python_mssql_login(self, icd):
        con = icd.con
        if con in self.attacks:
            attackid = self.attacks[con][1]
        try:
            self.cursor.execute("INSERT INTO logins (connection, login_username, login_password) VALUES (%s,%s,%s)",
                            (attackid, icd.username, icd.password))
            self.cursor.execute("INSERT INTO mssql_fingerprints (connection, mssql_fingerprint_hostname, mssql_fingerprint_appname, mssql_fingerprint_cltintname) VALUES (%s,%s,%s,%s)",
                            (attackid, icd.hostname, icd.appname, icd.cltintname))
        except Exception as e:
            print(e)

        self.dbh.commit()

    def handle_incident_dionaea_modules_python_mssql_cmd(self, icd):
        con = icd.con
        if con in self.attacks:
            attackid = self.attacks[con][1]
        try:
            self.cursor.execute("INSERT INTO mssql_commands (connection, mssql_command_status, mssql_command_cmd) VALUES (%s,%s,%s)",
                                (attackid, icd.status, icd.cmd))
        except Exception as e:
            print(e)

        self.dbh.commit()

    def handle_incident_dionaea_modules_python_virustotal_report(self, icd):
        md5 = icd.md5hash
        is_exist = self.cursor.execute("SELECT virustotal_md5_hash FROM virustotals  WHERE virustotal_md5_hash='%s'" % md5)
        if is_exist == 0: 
            if not self.vtapikey:
                try:
                    f = open(icd.path, mode='r')
                    j = json.load(f)
                except:
                    j = {'response_code': -2}
            else:
                url = 'https://www.virustotal.com/vtapi/v2/file/report'
                params = {'apikey': self.vtapikey, 'resource': md5}
                try:
                    response = requests.get(url, params=params)
                    j = response.json()
                    if j['response_code'] == -2:
                        time.sleep(63)
                        response = requests.get(url, params=params)
                        j = response.json()
                except:
                    j = {'response_code': -2}

            if j['response_code'] == 1: # file was known to virustotal
                permalink = j['permalink']
                # Convert UTC scan_date to Unix time  
                date = calendar.timegm(time.strptime(j['scan_date'], '%Y-%m-%d %H:%M:%S'))
                try:            
                    self.cursor.execute("INSERT INTO virustotals (virustotal_md5_hash, virustotal_permalink, virustotal_timestamp) VALUES (%s,%s,%s)",
                                        (md5, permalink, date))
                except Exception as e:
                    print(e)

                self.dbh.commit()

                virustotal = self.cursor.lastrowid

                scans = j['scans']
                for av, val in scans.items():
                    res = val['result']
                    # not detected = '' -> NULL
                    if res == '':
                        res = None
                    try:
                        self.cursor.execute("""INSERT INTO virustotalscans (virustotal, virustotalscan_scanner, virustotalscan_result) VALUES (%s,%s,%s)""",
                                            (virustotal, av, res))
                    except Exception as e:
                        print(e)
                   
                    logger.debug("scanner {} result {}".format(av,scans[av]))
                self.dbh.commit()

    def handle_incident_dionaea_modules_python_mysql_login(self, icd):
        con = icd.con
        if con in self.attacks:
            attackid = self.attacks[con][1]
        try:            
            self.cursor.execute("INSERT INTO logins (connection, login_username, login_password) VALUES (%s,%s,%s)",
                                (attackid, icd.username, icd.password))
        except Exception as e:
            print(e)

        self.dbh.commit()


    def handle_incident_dionaea_modules_python_mysql_command(self, icd):
        con = icd.con
        if con in self.attacks:
            attackid = self.attacks[con][1]
        try:            
            self.cursor.execute("INSERT INTO mysql_commands (connection, mysql_command_cmd) VALUES (%s,%s)",
                                (attackid, icd.command))
        except Exception as e:
            print(e)

        cmdid = self.cursor.lastrowid

        if hasattr(icd, 'args'):
            args = icd.args
            for i in range(len(args)):
                arg = args[i]
                try:
                    self.cursor.execute("INSERT INTO mysql_command_args (mysql_command, mysql_command_arg_index, mysql_command_arg_data) VALUES (%s,%s,%s)",
                                            (cmdid, i, arg))
                except Exception as e:
                    print(e)

        self.dbh.commit()

    def handle_incident_dionaea_modules_python_sip_command(self, icd):
        con = icd.con
        if con not in self.attacks:
            return

        def calc_allow(a):
            b={ b'UNKNOWN'  :(1<<0),
                'ACK'       :(1<<1),
                'BYE'       :(1<<2),
                'CANCEL'    :(1<<3),
                'INFO'      :(1<<4),
                'INVITE'    :(1<<5),
                'MESSAGE'   :(1<<6),
                'NOTIFY'    :(1<<7),
                'OPTIONS'   :(1<<8),
                'PRACK'     :(1<<9),
                'PUBLISH'   :(1<<10),
                'REFER'     :(1<<11),
                'REGISTER'  :(1<<12),
                'SUBSCRIBE' :(1<<13),
                'UPDATE'    :(1<<14)
                }
            allow=0
            for i in a:
                if i in b:
                    allow |= b[i]
                else:
                    allow |= b[b'UNKNOWN']
            return allow

        attackid = self.attacks[con][1]
        try:
            self.cursor.execute("""INSERT INTO sip_commands
                (connection, sip_command_method, sip_command_call_id,
                sip_command_user_agent, sip_command_allow) VALUES (%s,%s,%s,%s,%s)""",
                            (attackid, icd.method, icd.call_id, icd.user_agent, calc_allow(icd.allow)))
        except Exception as e:
            print(e)
        
        cmdid = self.cursor.lastrowid

        def add_addr(cmd, _type, addr):
            try:
                self.cursor.execute("""INSERT INTO sip_addrs
                    (sip_command, sip_addr_type, sip_addr_display_name,
                    sip_addr_uri_scheme, sip_addr_uri_user, sip_addr_uri_password,
                    sip_addr_uri_host, sip_addr_uri_port) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
                                (
                                    cmd, _type, addr['display_name'],
                                    addr['uri']['scheme'], addr['uri'][
                                        'user'], addr['uri']['password'],
                                    addr['uri']['host'], addr['uri']['port']
                                ))
            except Exception as e:
                print(e)

        add_addr(cmdid,'addr',icd.get('addr'))
        add_addr(cmdid,'to',icd.get('to'))
        add_addr(cmdid,'contact',icd.get('contact'))
        for i in icd.get('from'):
            add_addr(cmdid,'from',i)

        def add_via(cmd, via):
            try:
                self.cursor.execute("""INSERT INTO sip_vias
                    (sip_command, sip_via_protocol, sip_via_address, sip_via_port)
                    VALUES (%s,%s,%s,%s)""",
                                (
                                    cmd, via['protocol'],
                                    via['address'], via['port']
                                ))
            except Exception as e:
                print(e)


        for i in icd.get('via'):
            add_via(cmdid, i)

        def add_sdp(cmd, sdp):
            def add_origin(cmd, o):
                try:
                    self.cursor.execute("""INSERT INTO sip_sdp_origins
                            (sip_command, sip_sdp_origin_username,
                            sip_sdp_origin_sess_id, sip_sdp_origin_sess_version,
                            sip_sdp_origin_nettype, sip_sdp_origin_addrtype,
                            sip_sdp_origin_unicast_address)
                            VALUES (%s,%s,%s,%s,%s,%s,%s)""",
                                    (
                                        cmd, o['username'],
                                        o['sess_id'], o['sess_version'],
                                        o['nettype'], o['addrtype'],
                                        o['unicast_address']
                                    ))
                except Exception as e:
                    print(e)

            def add_condata(cmd, c):
                try:
                    self.cursor.execute("""INSERT INTO sip_sdp_connectiondatas
                            (sip_command, sip_sdp_connectiondata_nettype,
                            sip_sdp_connectiondata_addrtype, sip_sdp_connectiondata_connection_address,
                            sip_sdp_connectiondata_ttl, sip_sdp_connectiondata_number_of_addresses)
                            VALUES (%s,%s,%s,%s,%s,%s)""",
                                    (
                                        cmd, c['nettype'],
                                        c['addrtype'], c['connection_address'],
                                        c['ttl'], c['number_of_addresses']
                                    ))
                except Exception as e:
                    print(e)

            def add_media(cmd, c):
                try:
                    self.cursor.execute("""INSERT INTO sip_sdp_medias
                            (sip_command, sip_sdp_media_media,
                            sip_sdp_media_port, sip_sdp_media_number_of_ports,
                            sip_sdp_media_proto)
                            VALUES (%s,%s,%s,%s,%s)""",
                                    (
                                        cmd, c['media'],
                                        c['port'], c['number_of_ports'],
                                        c['proto']
                                    ))
                except Exception as e:
                    print(e)

            if 'o' in sdp:
                add_origin(cmd, sdp['o'])
            if 'c' in sdp:
                add_condata(cmd, sdp['c'])
            if 'm' in sdp:
                for i in sdp['m']:
                    add_media(cmd, i)

        if hasattr(icd,'sdp') and icd.sdp is not None:
            add_sdp(cmdid,icd.sdp)

        self.dbh.commit()

    def handle_incident_dionaea_modules_python_mqtt_connect(self, icd):
        con = icd.con
        if con in self.attacks:
            attackid = self.attacks[con][1]
            #self.cursor.execute("INSERT INTO logins (connection, login_username, login_password) VALUES (%s,%s,%s)",
            #    (attackid, icd.username, icd.password))
        try:
            self.cursor.execute("INSERT INTO mqtt_fingerprints (connection, mqtt_fingerprint_clientid, mqtt_fingerprint_willtopic, mqtt_fingerprint_willmessage,mqtt_fingerprint_username,mqtt_fingerprint_password) VALUES (?,?,?,?,?,?)",
                    (attackid, icd.clientid, icd.willtopic, icd.willmessage, icd.username, icd.password))
        except Exception as e:
            print(e)

        self.dbh.commit()

    def handle_incident_dionaea_modules_python_mqtt_publish(self, icd):
        con = icd.con
        if con in self.attacks:
            attackid = self.attacks[con][1]
        try:            
            self.cursor.execute("INSERT INTO mqtt_publish_commands (connection, mqtt_publish_command_topic, mqtt_publish_command_message) VALUES (%s,%s,%s)",
                    (attackid, icd.publishtopic, icd.publishmessage))
        except Exception as e:
            print(e)

        self.dbh.commit()

    def handle_incident_dionaea_modules_python_mqtt_subscribe(self, icd):
        con = icd.con
        if con in self.attacks:
            attackid = self.attacks[con][1]
        try:
            self.cursor.execute("INSERT INTO mqtt_subscribe_commands (connection, mqtt_subscribe_command_messageid, mqtt_subscribe_command_topic) VALUES (%s,%s,%s)",
                    (attackid, icd.subscribemessageid, icd.subscribetopic))
        except Exception as e:
            print(e)

        self.dbh.commit()
