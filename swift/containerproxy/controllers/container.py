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


from gettext import gettext as _
from urllib import unquote

from swift.common.utils import public
from swift.proxy.controllers.base import Controller, delay_denial, \
    cors_validation, update_headers, close_swift_conn
from swift.common.swob import HTTPBadRequest
from swift.common.bufferedhttp import http_connect_raw
from eventlet.timeout import Timeout
from swift.common.exceptions import ConnectionTimeout
from swift.common.swob import Response
from swift.common.http import  is_success, is_redirection, HTTP_NOT_FOUND

class ContainerController(Controller):
    def __init__(self, app, account_name, container_name, **kwargs):
        Controller.__init__(self, app)
        self.account_name = unquote(account_name)
        self.container_name = unquote(container_name)
        self.dbpool = self.app.dbpool

        self.sources = []
        self.statuses = []
        self.bodies =[]
        self.source_headers = []
        self.reasons = []

    def get_container_location_from_db(self):
        sql = 'SELECT location FROM location WHERE account_name = \'%s\' AND container_name = \'%s\'' \
              % (self.account_name, self.container_name)

        d = self.dbpool.queryone(sql)
        self.container_location = None
        if d is not None :
            return d[0]
        else:
            return None

    def get_container_host(self, req):
        container_location = None
        container_host = None
        if 'location' in req.headers and req.headers['location'] is not None:
            container_location = unquote(req.headers['location'])

        if container_location is None:
            container_location = self.get_container_location_from_db()

        if container_location and self.app.offsite_proxy_dict.has_key(self.container_location):
            container_host = self.app.offsite_proxy_dict[self.container_location]

        return container_host

    def put_container_location(self):
        sql = 'INSERT INTO location(account_name, container_name, location) VALUES (\'%s\', \'%s\', \'%s\')' \
              %(self.account_name, self.container_name, self.container_location)
        self.dbpool.execute(sql)

    def delete_container_host(self):
        sql = 'DELETE FROM location WHERE account_name = \'%s\' AND container_name = \'%s\'' \
              %(self.account_name, self.container_name)
        self.dbpool.execute(sql)

    def is_container_duplicate(self, req):
        for (k, v) in self.app.offsite_proxy_dict.items():
            try:
                with ConnectionTimeout(self.app.conn_timeout):
                    headers = self.generate_request_headers(req, additional=req.headers)
                    ipaddr, port = v.split(':')
                    conn = http_connect_raw(ipaddr, port, 'HEAD', req.path, headers=headers, query_string=req.query_string)

                with Timeout(self.app.node_timeout):
                    possible_source = conn.getresponse()
                    possible_source.swift_conn = conn
            except (Exception, Timeout):
               continue

            if possible_source and self.is_good_source(possible_source):
                return True

        return False

    def is_good_source(self, src):
        """
        Indicates whether or not the request made to the backend found
        what it was looking for.

        :param src: the response from the backend
        :returns: True if found, False if not
        """
        if isinstance(src.status, int):
            status = src.status
        else:
            status, reason = src.status.split(' ', 1)
        status = int(status)
        if self.server_type == 'Object' and status == 416:
            return True
        return is_success(status) or is_redirection(status)

    def forword_request(self, req, host=None):
        hosts = []
        source = None
        statuses = []
        bodies =[]
        source_headers = []
        reasons = []

        resp = Response(request=req)

        if host is None:
            hosts = [v for (k, v) in self.app.offsite_proxy_dict.items()]
        else:
            hosts.append(host)

        for hst in hosts:
            try:
                with ConnectionTimeout(self.app.conn_timeout):
                    headers = self.generate_request_headers(req, additional=req.headers)
                    ipaddr, port = hst.split(':')
                    conn = http_connect_raw(ipaddr, port, req.method, req.path, headers=headers, query_string=req.query_string)

                with Timeout(self.app.node_timeout):
                    possible_source = conn.getresponse()
                    possible_source.swift_conn = conn
            except (Exception, Timeout):
               continue

            if self.is_good_source(possible_source):
                if not float(possible_source.getheader('X-PUT-Timestamp', 1)):
                    statuses.append(HTTP_NOT_FOUND)
                    reasons.append('')
                    bodies.append('')
                    source_headers.append('')
                    close_swift_conn(possible_source)
                else:
                    statuses.append(possible_source.status)
                    reasons.append(possible_source.reason)
                    bodies.append('')
                    source_headers.append('')
                    source = possible_source
                    break
            else:
                statuses.append(possible_source.status)
                reasons.append(possible_source.reason)
                bodies.append(possible_source.read())
                source_headers.append(possible_source.getheaders())

        if source:
            close_swift_conn(source)
            update_headers(resp, source.getheaders())
            resp.accept_ranges = 'bytes'
            resp.content_length = source.getheader('Content-Length')
            if source.getheader('Content-Type'):
                resp.charset = None
                resp.content_type = source.getheader('Content-Type')
            resp.status = source.status
            resp.body = source.read()
        else:
            resp.status = statuses[0]
            resp.body = bodies[0]
            update_headers(resp, source_headers[0])

        return resp

    def GETorHEAD(self, req):
        container_host  = self.get_container_host(req)
        resp = self.forword_request(req, container_host)

        if self.is_good_source(resp):
            self.put_container_location()

        return resp

    @public
    @delay_denial
    @cors_validation
    def GET(self, req):
        return self.GETorHEAD(req)

    @public
    @delay_denial
    @cors_validation
    def HEAD(self, req):
        return self.GETorHEAD(req)

    @public
    @cors_validation
    def PUT(self, req):
        if self.is_container_duplicate(req):
            resp = HTTPBadRequest(request=req)
            resp.body = 'Container Name Duplicate '
            return resp

        container_host = self.get_container_host(req)

        res = self.forword_request(req, container_host)
        if self.is_good_source(res):
            self.put_container_location()

        return res

    @public
    @cors_validation
    def POST(self, req):
        container_host = self.get_container_host(req)
        return self.forword_request(req, container_host)

    @public
    @cors_validation
    def DELETE(self, req):
        container_host = self.get_container_host(req)
        res = self.forword_request(req, container_host)
        if self.is_good_source(res):
            self.delete_container_host()
        return res

