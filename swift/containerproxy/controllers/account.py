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

from urllib import unquote
from swift.common.utils import public
from swift.proxy.controllers.base import Controller
from swift.common.swob import Response
from swift.common.bufferedhttp import BufferedHTTPConnection
from eventlet.timeout import Timeout
from swift.common.exceptions import ConnectionTimeout
from swift.common.http import HTTP_NOT_FOUND
from swift.common.swob import HTTPServiceUnavailable
from swift.common.utils import json
from xml.sax import saxutils
from xml.etree import ElementTree

class AccountController(Controller):
    def __init__(self, app, account_name, **kwargs):
        Controller.__init__(self, app)
        self.account_name = unquote(account_name)
        if not self.app.allow_account_management:
            self.allowed_methods.remove('PUT')
            self.allowed_methods.remove('DELETE')

        self.dbpool = self.app.dbpool

    def get_container_location_from_db(self):
        sql = 'SELECT container_name, location FROM location WHERE account_name = %s' \
              % (self.account_name)

        table = self.dbpool.execute(sql)
        self.container_location_dict = None
        if table is not None and len(table) > 0:
            for row in table:
                self.container_location_dict[row[0]] = row[1]

    def get_container_host(self):
        self.get_container_location_from_db()
        for k, v in self.container_location_dict:
            if self.app.offsite_proxy_dict.has_key(v):
                self.container_location_dict[k] = self.app.offsite_proxy_dict[v]
            else:
                self.container_location_dict[k] = self.app.location

    def forword_request(self, req):
        self.get_container_host()
        if len(self.container_location_dict) <= 0:
            resp = HTTP_NOT_FOUND(request=req)
            resp.body = 'account deleted or has no container'
            return resp

        self.sources = None
        for k, v in self.container_location_dict:
            try:
                with ConnectionTimeout(self.app.conn_timeout):
                    headers = self.generate_request_headers(req, additional=req.headers)
                    conn = BufferedHTTPConnection(v)
                    conn.path = req.path_info
                    if req.query_string:
                        conn.path += '?' + req.query_string
                    conn.putrequest(req.method, conn.path, skip_host=(headers and 'Host' in headers))
                    if headers:
                        for header, value in headers.iteritems():
                            conn.putheader(header, str(value))
                        conn.endheaders()

                with Timeout(self.app.node_timeout):
                    self.sources.append(conn.getresponse())
                    conn.close()
            except (Exception, Timeout):
                pass

    def source_key(self, resp):
        """
        Provide the timestamp of the swift http response as a floating
        point value.  Used as a sort key.

        :param resp: httplib response object
        """
        return float(resp.getheader('x-put-timestamp') or
                     resp.getheader('x-timestamp') or 0)

    def update_headers(self, resp):
        self.sources.sort(key=lambda s: self.source_key(s[0]))
        for source in self.sources:
            if  'X-Account-Container-Count' in source.headers:
                resp.headers['X-Account-Container-Count'] += source.headers['X-Account-Container-Count']

            if 'X-Account-Object-Count' in source.headers:
                resp.headers['X-Account-Object-Count'] += source.headers['X-Account-Object-Count']

            if 'X-Account-Bytes-Used' in source.headers:
                resp.headers['X-Account-Bytes-Used'] += source.headers['X-Account-Bytes-Used']

            if 'X-Timestamp' in source.headers:
                if 'X-Timestamp' not in resp.headers:
                    resp.headers['X-Timestamp'] = source.headers['X-Timestamp']
                elif resp.headers['X-Timestamp'] > source.headers['X-Timestamp']:
                    resp.headers['X-Timestamp'] = source.headers['X-Timestamp']

            if 'X-PUT-Timestamp' in source.headers:
                if 'X-PUT-Timestamp' not in resp.headers:
                    resp.headers['X-PUT-Timestamp'] = source.headers['X-PUT-Timestamp']
                elif resp.headers['X-PUT-Timestamp'] > source.headers['X-PUT-Timestamp']:
                    resp.headers['X-PUT-Timestamp'] = source.headers['X-PUT-Timestamp']

            resp.content_type = source.headers['Content-Type']
            resp.status = source.status
            if not resp.environ:
                resp.environ = {}
            resp.environ['swift_x_timestamp'] = \
                resp.headers['X-Timestamp']
            resp.accept_ranges = 'bytes'
        return resp


    @public
    def HEAD(self, req):
        self.forword_request(req)
        if self.sources:
            resp = Response(request=req)
            resp = self.update_headers(resp)
            resp.content_length = 0
            return resp

        resp = HTTPServiceUnavailable(request=req)
        return resp

    @public
    def GET(self, req):
        self.forword_request(req)
        if self.sources:
            resp = Response(request=req)
            resp = self.update_headers(resp)
            bodies = []
            if resp.content_type == 'application/json':
                for source in self.sources:
                    bodies.extend(json.loads(source.read()))
                bodies = json.dumps(bodies)
            elif resp.content_type.endswith('/xml'):
                bodies = ['<?xml version="1.0" encoding="UTF-8"?>',
                       '<account name=%s>' % saxutils.quoteattr(self.account_name)]
                for source in self.sources:
                    root = ElementTree.fromstring(source.read())
                    lst_node = root.getiterator("container")
                    for node in lst_node:
                        item =  '<container><name>%s</name><count>%s</count>' \
                       '<bytes>%s</bytes></container>' % \
                       (node.find('name').text, node.find('count').text, node.find('bytes').text)
                        bodies.append(item)
                bodies.append('</account>')

            resp.body = '\n'.join(bodies)
            resp.content_length = len(resp.body)
            return resp

        resp = HTTPServiceUnavailable(request=req)
        return resp

    @public
    def PUT(self, req):
        pass

    @public
    def POST(self, req):
        self.forword_request(req)
        if self.sources:
            source = self.sources.pop()
            resp = Response(request=req, conditional_response=True)
            resp.status = source.status
            resp = self.update_headers(resp)
            resp.content_type = source.headers('Content-Type')
            resp.content_length = source.getheader('Content-Length')

            return resp

        resp = HTTPServiceUnavailable(request=req)
        return resp

    @public
    def DELETE(self, req):
        pass