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
    cors_validation, update_headers
from swift.common.swob import HTTPBadRequest
from swift.common.bufferedhttp import http_connect_raw
from eventlet.timeout import Timeout
from swift.common.exceptions import ConnectionTimeout
from swift.common.swob import Response
from swift.common.http import  is_success, is_redirection

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
        self.container_host = None
        self.container_location = None

    def clean_acls(self, req):
        if 'swift.clean_acl' in req.environ:
            for header in ('x-container-read', 'x-container-write'):
                if header in req.headers:
                    try:
                        req.headers[header] = \
                            req.environ['swift.clean_acl'](header,
                                                           req.headers[header])
                    except ValueError, err:
                        return HTTPBadRequest(request=req, body=str(err))
        return None

    def get_container_location_from_db(self):
        sql = 'SELECT location FROM location WHERE account_name = \'%s\' AND container_name = \'%s\'' \
              % (self.account_name, self.container_name)

        d = self.dbpool.queryone(sql)
        self.container_location = None
        if d is not None :
            for row in d:
                self.container_location = row[0]

    def get_container_location_from_request(self, req):
        if 'location' not in req.headers or req.headers['location'] is None:
            self.container_location =  self.app.location
        else:
            self.container_location = unquote(req.headers['location'])

    def get_container_host(self):
        if self.container_location is None:
            self.get_container_location_from_db()
        if self.container_location is None:
            self.container_location = self.app.location

        if self.app.offsite_proxy_dict.has_key(self.container_location):
            self.container_host = self.app.offsite_proxy_dict[self.container_location]

    def put_container_location(self):
        sql = 'INSERT INTO location(account_name, container_name, location) VALUES (\'%s\', \'%s\', \'%s\')' \
              %(self.account_name, self.container_name, self.container_location)
        self.dbpool.execute(sql)

    def delete_container_host(self):
        sql = 'DELETE FROM location WHERE account_name = \'%s\' AND container_name = \'%s\'' \
              %(self.account_name, self.container_name)
        self.dbpool.execute(sql)

    def is_container_duplicate(self):
        sql = 'SELECT * from location WHERE account_name = \'%s\' AND container_name = \'%s\'' \
              % (self.account_name, self.container_name)

        table = self.dbpool.queryone(sql)
        if not table:
            return False

        return True

    def is_good_source(self, src):
        """
        Indicates whether or not the request made to the backend found
        what it was looking for.

        :param src: the response from the backend
        :returns: True if found, False if not
        """
        status, reason = src.status.split(' ')
        status = int(status)
        if self.server_type == 'Object' and status == 416:
            return True
        return is_success(status) or is_redirection(status)

    def forword_request(self, req):
        res = Response(request=req)
        if self.container_host is not None:
            possible_source = None
            try:
                with ConnectionTimeout(self.app.conn_timeout):
                    headers = self.generate_request_headers(req, additional=req.headers)
                    ipaddr, port = self.container_host.split(':')
                    conn = http_connect_raw(ipaddr, port, req.method, req.path, headers=headers, query_string=req.query_string)

                with Timeout(self.app.node_timeout):
                    possible_source = conn.getresponse()
                    possible_source.swift_conn = conn
            except (Exception, Timeout):
                print "timeout"

            if possible_source is not None:
                res.status = possible_source.status
                res.body = possible_source.read()
                update_headers(res, possible_source.getheaders())
                return res

        res.status = '503 Internal Server Error'
        return res

    def GETorHEAD(self, req):
        self.get_container_host()
        return self.forword_request(req)

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
        if self.is_container_duplicate():
            resp = HTTPBadRequest(request=req)
            resp.body = 'container is duplicate'
            return resp

        self.get_container_location_from_request(req)
        self.get_container_host()

        res = self.forword_request(req)
        if self.is_good_source(res):
            self.put_container_location()

        return res

    @public
    @cors_validation
    def POST(self, req):
        self.get_container_host()
        return self.forword_request(req)

    @public
    @cors_validation
    def DELETE(self, req):
        self.get_container_host()
        res = self.forword_request(req)
        if self.is_good_source(res):
            self.delete_container_host()
        return res

