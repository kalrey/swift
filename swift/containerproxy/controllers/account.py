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
from swift.common.utils import public, config_true_value
from swift.proxy.controllers.base import Controller, close_swift_conn
from swift.common.swob import Response
from swift.common.bufferedhttp import http_connect_raw
from eventlet.timeout import Timeout
from swift.common.exceptions import ConnectionTimeout
from swift.common.swob import HTTPServiceUnavailable
from swift.common.utils import json
from xml.sax import saxutils
from xml.etree import ElementTree
from swift.common.http import  is_success, is_redirection, HTTP_NOT_FOUND

class AccountController(Controller):
    def __init__(self, app, account_name, **kwargs):
        self.account_name = unquote(account_name)
        self.app = app
        self.dbpool = self.app.dbpool
        self.used_source_etag = ''

        self.sources = []
        self.statuses = []
        self.bodies =[]
        self.source_headers = []
        self.reasons = []

    def get_container_location_from_db(self):
        sql = 'SELECT container_name, location FROM location WHERE account_name = \'%s\'' \
              % (self.account_name)

        table = self.dbpool.queryall(sql)
        self.container_location_dict = None
        if table is not None > 0:
            for row in table:
                self.container_location_dict[row[0]] = row[1]

    def get_container_host(self):
        self.get_container_location_from_db()
        if self.container_location_dict:
            for (k, v) in self.container_location_dict.items():
                if self.app.offsite_proxy_dict.has_key(v):
                    self.container_location_dict[k] = self.app.offsite_proxy_dict[v]
                else:
                    self.container_location_dict[k] = self.app.location

    def is_good_source(self, src):
        """
        Indicates whether or not the request made to the backend found
        what it was looking for.

        :param src: the response from the backend
        :returns: True if found, False if not
        """
        if self.server_type == 'Object' and src.status == 416:
            return True
        return is_success(src.status) or is_redirection(src.status)

    def forword_request(self, req):
        newest = config_true_value(req.headers.get('x-newest', 'f'))
        for (k, v) in self.app.offsite_proxy_dict.items():
            try:
                with ConnectionTimeout(self.app.conn_timeout):
                    headers = self.generate_request_headers(req, additional=req.headers)
                    ipaddr, port = v.split(':')
                    conn = http_connect_raw(ipaddr, port, req.method, req.path, headers=headers, query_string=req.query_string)

                with Timeout(self.app.node_timeout):
                    possible_source = conn.getresponse()
                    possible_source.swift_conn = conn
            except (Exception, Timeout):
               continue

            if self.is_good_source(possible_source):
                if not float(possible_source.getheader('X-PUT-Timestamp', 1)):
                    self.statuses.append(HTTP_NOT_FOUND)
                    self.reasons.append('')
                    self.bodies.append('')
                    self.source_headers.append('')
                    close_swift_conn(possible_source)
                else:
                    src_headers = dict(
                            (k.lower(), v) for k, v in
                            possible_source.getheaders())
                    if src_headers.get('etag', '').strip('"') != \
                                self.used_source_etag:
                            self.statuses.append(HTTP_NOT_FOUND)
                            self.reasons.append('')
                            self.bodies.append('')
                            self.source_headers.append('')
                            continue

                    self.statuses.append(possible_source.status)
                    self.reasons.append(possible_source.reason)
                    self.bodies.append('')
                    self.source_headers.append('')
                    self.sources.append(possible_source)
                    if not newest:  # one good source is enough
                        break
            else:
                self.statuses.append(possible_source.status)
                self.reasons.append(possible_source.reason)
                self.bodies.append(possible_source.read())
                self.source_headers.append(possible_source.getheaders())

    def get_working_response(self, req):
        resp = None
        if self.sources:
            resp = Response(request=req)
            resp = self.update_headers(resp)
            account_list = []
            if resp.content_type == 'application/json':
                data = []
                for source in self.sources:
                    d = source.read()
                    if d and len(d) > 0:
                        data.extend(json.loads(d))
                        account_list = json.dumps(data)
            elif resp.content_type.endswith('/xml'):
                output_list = ['<?xml version="1.0" encoding="UTF-8"?>',
                               '<account name=%s>' % saxutils.quoteattr(self.account_name)]
                for source in self.sources:
                    d = source.read()
                    if d and len(d) > 0:
                        root = ElementTree.fromstring(d)
                        lst_node = root.getiterator("container")
                        for node in lst_node:
                            item =  '<container><name>%s</name><count>%s</count>' \
                                '<bytes>%s</bytes></container>' % \
                                (node.find('name').text, node.find('count').text, node.find('bytes').text)
                            output_list.append(item)

                output_list.append('</account>')
                account_list = '\n'.join(output_list)
            else:
                output_list = ''
                for source in self.sources:
                    d = source.read()
                    if d and len(d) > 0:
                        output_list += d
                account_list = output_list

            resp.body = account_list
            resp.content_length = len(resp.body)

        return resp

    def source_key(self, resp):
        """
        Provide the timestamp of the swift http response as a floating
        point value.  Used as a sort key.

        :param resp: httplib response object
        """
        return float(resp.getheader('x-put-timestamp') or
                     resp.getheader('x-timestamp') or 0)

    def update_headers(self, resp):
        for source in self.sources:
            if  source.getheader('X-Account-Container-Count', None) is not None:
                if 'X-Account-Container-Count' not in resp.headers:
                    resp.headers['X-Account-Container-Count'] = int(source.getheader('X-Account-Container-Count'))
                else:
                    resp.headers['X-Account-Container-Count'] = int(resp.headers['X-Account-Container-Count'])   + \
                                                                int(source.getheader('X-Account-Container-Count'))
            if  source.getheader('X-Account-Object-Count', None) is not None:
                if 'X-Account-Object-Count' not in resp.headers:
                    resp.headers['X-Account-Object-Count'] = int(source.getheader('X-Account-Object-Count'))
                else:
                    resp.headers['X-Account-Object-Count'] = int(resp.headers['X-Account-Object-Count'])   + \
                                                                int(source.getheader('X-Account-Object-Count'))

            if  source.getheader('X-Account-Bytes-Used', None) is not None:
                if 'X-Account-Bytes-Used' not in resp.headers:
                    resp.headers['X-Account-Bytes-Used'] = int(source.getheader('X-Account-Bytes-Used'))
                else:
                    resp.headers['X-Account-Bytes-Used'] = int(resp.headers['X-Account-Bytes-Used'])   + \
                                                                int(source.getheader('X-Account-Bytes-Used'))

            if source.getheader('X-Timestamp', None) is not None:
                if 'X-Timestamp' not in resp.headers:
                    resp.headers['X-Timestamp'] = source.getheader('X-Timestamp')
                elif resp.headers['X-Timestamp'] > source.getheader('X-Timestamp'):
                    resp.headers['X-Timestamp'] = source.getheader('X-Timestamp')

            if source.getheader('X-PUT-Timestamp', None) is not None:
                if 'X-PUT-Timestamp' not in resp.headers:
                    resp.headers['X-PUT-Timestamp'] = source.getheader('X-PUT-Timestamp')
                elif resp.headers['X-PUT-Timestamp'] > source.getheader('X-PUT-Timestamp'):
                    resp.headers['X-PUT-Timestamp'] = source.getheader('X-PUT-Timestamp')

            if  source.getheader('Content-Type', None) is not None:
                resp.content_type = source.getheader('Content-Type')

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
        res = self.get_working_response(req)
        if not res:
            res = self.best_response(req, self.statuses, self.reasons, self.bodies, '%s %s' %('container-proxy', req.method))

        return res

    @public
    def GET(self, req):
        self.forword_request(req)
        res = self.get_working_response(req)
        if not res:
            res = self.best_response(req, self.statuses, self.reasons, self.bodies, '%s %s' %('container-proxy', req.method))

        return res

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

            headers = source.getheaders()
            resp.content_type = headers('Content-Type')
            resp.content_length = headers('Content-Length')

            return resp

        resp = HTTPServiceUnavailable(request=req)
        return resp

    @public
    def DELETE(self, req):
        pass