__author__ = 'kalrey'


import logging
import requests
#modify by byliu
#from keystoneclient.openstack.common import jsonutils
import json as jsonutils
#end by byliu
from swift.common.utils import cache_from_env

class NetworkError(Exception):
    pass


class ServiceError(Exception):
    pass


class Name2Id(object):

    def __init__(self, app, conf):
        self.LOG = logging.getLogger(conf.get('log_name', __name__))
        self.LOG.info('Starting Name2Id patch middleware')
        self.app = app
        self.conf = conf
        self.auth_uri = self.conf.get('auth_uri')
        self.admin_token = self.conf.get('admin_token')

        self.http_connect_timeout = int(self.conf.get('http_connect_timeout', 1))
        self.auth_uri = self.auth_uri.rstrip('/')
        self.memcache_client = None

    def _http_request(self, method, path, **kwargs):
        url = '%s/%s' % (self.auth_uri, path.lstrip('/'))
        kwargs.setdefault('timeout', self.http_connect_timeout)

        try:
            response = requests.request(method, url, **kwargs)
        except Exception, e:
            raise NetworkError('Unable to communicate with keystone')

        return response

    def _json_request(self, method, path, body=None, additional_headers=None):
        """HTTP request helper used to make json requests.

        :param method: http method
        :param path: relative request url
        :param body: dict to encode to json as request body. Optional.
        :param additional_headers: dict of additional headers to send with
                                   http request. Optional.
        :return (http response object, response body parsed as json)
        :raise ServerError when unable to communicate with keystone

        """
        kwargs = {
            'headers': {
                'Content-type': 'application/json',
                'Accept': 'application/json',
            },
        }

        if additional_headers:
            kwargs['headers'].update(additional_headers)

        if body:
            kwargs['data'] = jsonutils.dumps(body)

        response = self._http_request(method, path, **kwargs)

        try:
            data = jsonutils.loads(response.text)
        except ValueError:
            data = {}

        return response, data

    def get_tenant_id_from_cache(self, tenant_name):
        key = '(tenant_id/%s)' % tenant_name

        return self.memcache_client.get(key)

    def cache_tenant_id(self, tenant_name, tenant_id):
        key = '(tenant_id/%s)' % tenant_name
        self.memcache_client.set(key, tenant_id, time=86400)

    def get_tenant_id(self, env, tenant_name):
        self.memcache_client = cache_from_env(env)

        tenant_id = self.get_tenant_id_from_cache(tenant_name)
        if tenant_id:
            return tenant_id

        if tenant_name is None:
            return None

        header = {"X-Auth-Token": self.admin_token}
        path = '/v2.0/tenants?name=%s' % tenant_name

        resp, data = self._json_request('GET', path, additional_headers=header)
        try:
            tenant_id = data['tenant']['id']
            self.cache_tenant_id(tenant_name, tenant_id)
            return tenant_id
        except (AssertionError, KeyError, ValueError):
            raise ServiceError('Invalid json response')


    def __call__(self, environ, start_response):
        environ['swift.name2id.ORIG_PATH_INFO'] = environ['PATH_INFO']
        if environ['PATH_INFO'].startswith('/v1/AUTH_'):
            return self.app(environ, start_response)
        else:
            try:
                path_parts = environ['PATH_INFO'].split('/')
                if len(path_parts) > 2:
                    tenant_name = path_parts[2]
                    tenant_id = self.get_tenant_id(environ, tenant_name)
                    path_parts[2] = 'AUTH_' + tenant_id
                    environ['PATH_INFO'] = '/'.join(path_parts)
            except Exception as e:
                self.LOG.error(e)
                pass
        return self.app(environ, start_response)


def filter_factory(global_conf, **local_conf):
    conf = global_conf
    conf.update(local_conf)

    def name2id_filter(app):
        return Name2Id(app, conf)
    return name2id_filter
