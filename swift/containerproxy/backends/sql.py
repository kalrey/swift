# Copyright (c) 2010-2012 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from DBUtils.PooledDB import PooledDB
import MySQLdb
import  re

class SwiftPooledDB(object):
    def __init__(self, connection):
        self.username = None
        self.password = None
        self.host = None
        self.database = None
        self.parse_rfc1738_args(connection)
        self._pool = PooledDB(MySQLdb, mincached=0, maxcached=10, maxshared=10, maxusage=20,host=self.host, user=self.username, passwd=self.password, db=self.database, autocommit=True)

    def parse_rfc1738_args(self, connection):
        pattern = re.compile(r'''
            (?P<name>[\w\+]+)://
            (?:
                (?P<username>[^:/]*)
                (?::(?P<password>.*))?
            @)?
            (?:
                (?:
                    \[(?P<ipv6host>[^/]+)\] |
                    (?P<ipv4host>[^/:]+)
                )?
                (?::(?P<port>[^/]*))?
            )?
            (?:/(?P<database>.*))?
            ''', re.X)
        m = pattern.match(connection)
        if m is not None:
            components = m.groupdict()
            if components['database'] is not None:
                tokens = components['database'].split('?', 2)
                self.database = tokens[0]

            if components['username'] is not None:
                self.username = self._rfc_1738_unquote(components['username'])
            if components['password'] is not None:
                self.password = self._rfc_1738_unquote(components['password'])

            ipv4host = components.pop('ipv4host')
            ipv6host = components.pop('ipv6host')
            self.host = ipv4host or ipv6host

    def _rfc_1738_unquote(self, text):
        from urllib import unquote
        return unquote(text)

    def get_conn(self):
        return self._pool.connection()

    def execute(self, sql):
        rowcount = 0
        try:
            conn = self.get_conn()
            cursor = conn.cursor()
            rowcount = cursor.execute(sql)
            cursor.close()
            conn.close()
        except Exception, e:
            print e

        return rowcount

    def queryone(self, sql):
        res = None
        try:
            conn = self.get_conn()
            cursor = conn.cursor()
            rowcount = cursor.execute(sql)
            if rowcount > 0:
                res = cursor.fetchone()
            else:
                res = None

            cursor.close()
            conn.close()
        except Exception, e:
            print e

        return res

    def queryall(self, sql):
        res = None
        try:
            conn = self.get_conn()
            cursor = conn.cursor()
            rowcount = cursor.execute(sql)
            if rowcount > 0:
                res = cursor.fetchall()
            else:
                res = None

            cursor.close()
            conn.close()
        except Exception, e:
            print e

        return res


