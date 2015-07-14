# -*- coding:utf-8 -*-
# Copyright (c) 2010-2012 OpenStack Foundation
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
"""
    signer = Ec2Signer('6b7362b058a24000af041903b314795a')
    credentials = {'access_key': '841bd27b5ecc48c18d828f6007bfc400',
                   'signature': 'NMXt4APHJYqeMVq9Oz5nRyAPb6E=',
                   'verb': 'POST',
                   'content-md5': 'AF09413F37E16598A7A4EBF5CC1D11CA',
                   'content-type': 'image/jpeg',
                   'timestamp': 'Thu, 15 Jan 2015 06:31:06 GMT',
                   'path': '/ssstest/中文.jpg',
                   'headers': {"x-object-meta-fruit":"obj"}}
    print signer.generate(credentials)
"""


from swift.common import utils as swift_utils
from swift.common.swob import Request
import datetime
import hashlib
import requests
import json
import time
import six
import hmac
import base64
import re
import iso8601
from keystoneclient import access
from swift.common.utils import cache_from_env
from keystoneclient.contrib.ec2.utils import Ec2Signer as KeystoneEc2Signer

CACHE_KEY_TEMPLATE = 'access_key/%s'

def _token_is_v2(token_info):
    return ('access' in token_info)

def _token_is_v3(token_info):
    return ('token' in token_info)

def _v3_to_v2_catalog(catalog):
    """Convert a catalog to v2 format.

    X_SERVICE_CATALOG must be specified in v2 format. If you get a token
    that is in v3 convert it.
    """
    v2_services = []
    for v3_service in catalog:
        # first copy over the entries we allow for the service
        v2_service = {'type': v3_service['type']}
        try:
            v2_service['name'] = v3_service['name']
        except KeyError:
            pass

        # now convert the endpoints. Because in v3 we specify region per
        # URL not per group we have to collect all the entries of the same
        # region together before adding it to the new service.
        regions = {}
        for v3_endpoint in v3_service.get('endpoints', []):
            region_name = v3_endpoint.get('region')
            try:
                region = regions[region_name]
            except KeyError:
                region = {'region': region_name} if region_name else {}
                regions[region_name] = region

            interface_name = v3_endpoint['interface'].lower() + 'URL'
            region[interface_name] = v3_endpoint['url']

        v2_service['endpoints'] = list(regions.values())
        v2_services.append(v2_service)

    return v2_services


def parse_isotime(timestr):
    """Parse time from ISO 8601 format."""
    try:
        return iso8601.parse_date(timestr)
    except iso8601.ParseError as e:
        raise ValueError(six.text_type(e))
    except TypeError as e:
        raise ValueError(six.text_type(e))


def normalize_time(timestamp):
    """Normalize time in arbitrary timezone to UTC naive object."""
    offset = timestamp.utcoffset()
    if offset is None:
        return timestamp
    return timestamp.replace(tzinfo=None) - offset


class NetworkError(Exception):
    pass


class ServiceError(Exception):
    pass


class InvalidUserToken(Exception):
    pass


class ConfigurationError(Exception):
    pass


class InvalidSignature(Exception):
    pass


class InvalidDateError(Exception):
    pass


class SignatureExpireError(Exception):
    pass


class SignatureExpireFormatError(Exception):
    pass


class MiniResp(object):
    def __init__(self, error_message, env, headers=[]):
        # The HEAD method is unique: it must never return a body, even if
        # it reports an error (RFC-2616 clause 9.4). We relieve callers
        # from varying the error responses depending on the method.
        if env['REQUEST_METHOD'] == 'HEAD':
            self.body = ['']
        else:
            self.body = [error_message]
        self.headers = list(headers)
        self.headers.append(('Content-type', 'text/plain'))


class Ec2Signer(object):
    def __init__(self, secret_key, logger=None):
        self.secret_key = secret_key.encode()
        self.logger = logger

    def generate(self, credentials):
        string_to_sign = self.string_to_sign(credentials)
        h = hmac.new(self.secret_key, self._get_utf8_value(string_to_sign), hashlib.sha1)
        return base64.encodestring(h.digest()).strip()

    def string_to_sign(self, credentials):
        verb = credentials['verb']
        content_md5 = credentials.get('content-md5', '')
        content_type = credentials.get('content-type', '')
        timestamp = credentials.get('timestamp')
        canonicalize_headers = self.get_canonicalized_headers(credentials)
        canonicalize_resource = self.get_canonicalized_resource(credentials)

        sign_string = '\n'.join((verb, content_md5, content_type, timestamp)) + '\n'
        if canonicalize_headers:
            sign_string = '%s%s' % (sign_string, canonicalize_headers) + '\n'

        sign_string = '%s%s' %(sign_string, canonicalize_resource)

        if self.logger:
            self.logger.warn('string_to_sign %s' % sign_string)

        return sign_string

    def get_canonicalized_resource(self, credentials):
        return credentials['path']

    def get_canonicalized_headers(self, credentials):
        headers_lower = dict((k.lower().strip(), v.strip())
                             for (k, v) in six.iteritems(credentials['headers']))
        headers_lower = sorted(six.iteritems(headers_lower), key=lambda d: d[0])
        header_list = []
        for (k,v) in headers_lower:
            header_list.append('%s:%s' % (k, v))

        return '\n'.join(header_list)

    @staticmethod
    def _get_utf8_value(value):
        """Get the UTF8-encoded version of a value."""
        if not isinstance(value, (six.binary_type, six.text_type)):
            value = str(value)
        if isinstance(value, six.text_type):
            return value.encode('utf-8')
        else:
            return value


class SignatureAuthMiddleware(object):
    def __init__(self, app, conf):
        self.app = app
        self.conf = conf
        self.identity_uri = self.conf.get('auth_uri')
        self.logger = swift_utils.get_logger(conf, log_route='signature_auth')
        self.logger.info('Starting signature authenticate middleware')
        self.http_request_max_retries = self.conf.get('http_request_max_retries', 0)
        http_connect_timeout_cfg = self.conf.get('http_connect_timeout', 3000)
        self.http_connect_timeout = (http_connect_timeout_cfg and
                                     int(http_connect_timeout_cfg))
        self.memcache_client = None

    def _validate_signature(self, env):
        signature = env.get('HTTP_AUTHORIZATION')
        if not signature.startswith('CSSP') or ':' not in signature:
            raise InvalidSignature('Invalid Signature Format')

        access_key, sign = signature[5:].split(':')
        access_key = access_key.strip()
        sign = sign.strip()

        req = Request(env)

        if not req.headers.get('date'):
            raise InvalidDateError('Invalid Header Date')

        gmt_date = req.headers.get('date')

        self.check_signature_expire(gmt_date)

        ver, account, container, obj = req.split_path(
                2, 4, rest_with_last=True)


        canonicalize_headers = {}
        canonicalize_resource = ""

        if obj:
            canonicalize_resource = '%s/%s' %(container, obj)
        elif container:
            canonicalize_resource = container

        canonicalize_resource = '/%s' % canonicalize_resource

        header_prex = 'x-object-meta'
        headers_lower = dict((k.lower(), v)
                             for (k, v) in six.iteritems(req.headers))
        for k in headers_lower.keys():
            if k.startswith(header_prex):
                if canonicalize_headers.has_key(k):
                    canonicalize_headers[k] = '%s,%s' % (canonicalize_headers[k], headers_lower.get(k))
                else:
                    canonicalize_headers[k] = headers_lower[k]

        content_type = req.headers.get('content-type')
        if not content_type:
            content_type = ''

	content_md5 = req.headers.get('content-md5') or req.headers.get('etag')
        if not content_md5:
            content_md5 = ''

        credentials = {'signature': sign,
                       'verb': req.method,
                       'content-md5': content_md5,
                       'content-type': content_type,
                       'timestamp': gmt_date,
                       'path': canonicalize_resource,
                       'headers': canonicalize_headers}

        secret_key, token_data = self._get_cache_data(access_key)
	secret_key = None
	token_data = None
        if not secret_key:
            secret_key = self._get_secret_key(access_key)
            self._set_cache_data(access_key, secret_key)

        self.check_signature(secret_key, credentials)

        if token_data and self._will_expire_soon(token_data):
            token_data = None

        if not token_data:
            token_data = self._get_ec2_token(access_key, secret_key, req.method)
            self._set_cache_data(access_key, secret_key, token_data)

        return token_data


    def _http_request(self, method, path, **kwargs):
        """HTTP request helper used to make unspecified content type requests.

        :param method: http method
        :param path: relative request url
        :return (http response object, response body)
        :raise ServerError when unable to communicate with keystone

        """
        url = '%s/%s' % (self.identity_uri, path.lstrip('/'))

        kwargs.setdefault('timeout', self.http_connect_timeout)

        RETRIES = self.http_request_max_retries
        retry = 0
        while True:
            try:
                response = requests.request(method, url, **kwargs)
                break
            except Exception as e:
                if retry >= RETRIES:
                    self.logger.error('HTTP connection exception: %s', e)
                    raise NetworkError('Unable to communicate with keystone')
                # NOTE(vish): sleep 0.5, 1, 2
                self.logger.warn('Retrying on HTTP connection exception: %s', e)
                time.sleep(2.0 ** retry / 2)
                retry += 1

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
            kwargs['data'] = json.dumps(body)

        response = self._http_request(method, path, **kwargs)

        try:
            data = json.loads(response.text)
        except ValueError:
            self.logger.debug('Keystone did not return json-encoded body')
            data = {}

        return response, data

    def check_signature_expire(self, date):
        try:
	    gmt_format = "%a, %d %b %Y %H:%M:%S GMT"
            expire_time = datetime.datetime.strptime(date, gmt_format)
	except Exception:
	    raise SignatureExpireFormatError('Date Format Error')

        now = datetime.datetime.utcnow()

        if expire_time > now and ( expire_time-now ) > datetime.timedelta(minutes=15):
            raise SignatureExpireError('Date Expire Error')

        if now > expire_time and (now - expire_time) > datetime.timedelta(minutes=15):
            raise SignatureExpireError('Date Expire Error')

    def _get_cache_data(self, access_key):
        data = self.memcache_client.get(CACHE_KEY_TEMPLATE % access_key)
        if not data:
            return None, None

        if '|' not in data:
            return data, None

        data_split = data.split('|')

        return data_split[0], json.loads(data_split[1])

    def _set_cache_data(self, access_key, secret_key, token=None):
        data = secret_key
        if secret_key and token:
            data = '%s|%s' %(secret_key, json.dumps(token))

        self.memcache_client.set(CACHE_KEY_TEMPLATE % access_key, data, time=86400, serialize=False)

    def _get_secret_key(self, access_key):
        response, data = self._json_request('GET', '/v2.0/credentials/OS-EC2/%s' % access_key)
        try:
            credential = data['credential']
            secret = credential['secret']
        except (AssertionError, KeyError, ValueError) as e:
            self.logger.warn('keystone did not return credential body, %s, %s', response.status_code, str(data))
            raise ServiceError('invalid credential response')
        return secret

    def _get_ec2_token(self, access_key, secret_key, method):
        gmt_format = "%a, %d %b %Y %H:%M:%S GMT"
        credentials = {"credentials" : {"params":{"SignatureVersion": '0',
                                                  "Action":method ,
                                                  "Timestamp": datetime.datetime.utcnow().strftime(gmt_format)},
                                        "access": access_key}}
        signer = KeystoneEc2Signer(secret_key)
        signature = signer.generate(credentials['credentials'])
        credentials["credentials"]["signature"] = signature

        response, token_data = self._json_request('POST', '/v2.0/ec2tokens', body=credentials)
        try:
            token_id = token_data['access']['token']['id']
        except (AssertionError, KeyError):
            self.logger.warn(
                'Unexpected response from keystone service: %s', token_data)
            raise ServiceError('invalid json response')
        except ValueError:
            token_data['access']['token']['id'] = '<SANITIZED>'
            self.logger.warn(
                'Unable to parse expiration time from token: %s', token_data)
            raise ServiceError('invalid json response')

        return token_data

    def check_signature(self, secret_key, credentials):
        signer = Ec2Signer(secret_key, self.logger)
        signature = signer.generate(credentials)
	self.logger.warn('check Signature, in %s, current %s' % (credentials['signature'], signature))
        if self.auth_str_equal(credentials['signature'], signature):
            return
        else:
            raise InvalidSignature('Invalid EC2 signature.')

    def _will_expire_soon(self, token_data):
        try:
            expire = token_data['access']['token']['expires']
            if not expire:
                raise AssertionError('expire')
            datetime_expiry = normalize_time(parse_isotime(expire))
            soon = (datetime.datetime.utcnow() + datetime.timedelta(seconds=30))
        except (AssertionError, KeyError):
            self.logger.warn(
                'Unexpected response from token: %s', token_data)
            raise ServiceError('invalid token data')
        except ValueError:
            self.logger.warn(
                'Unable to parse expiration time from token: %s', token_data)
            raise ServiceError('invalid token data')

        return datetime_expiry < soon

    def __call__(self, env, start_response):
        self.memcache_client = cache_from_env(env)
        token = env.get('HTTP_X_AUTH_TOKEN', env.get('HTTP_X_STORAGE_TOKEN', None))
        signature = env.get('HTTP_AUTHORIZATION')
        if token or not signature:
            return self.app(env, start_response)

        try:
            now = datetime.datetime.now()
            token_info = self._validate_signature(env)
            perf = (datetime.datetime.now() - now).microseconds / 1000
            self.logger.info('perf of validate signature is %d' % perf)
            self._remove_auth_headers(env)
            env['keystone.token_info'] = token_info
            user_headers = self._build_user_headers(token_info)
            self._add_headers(env, user_headers)
            return self.app(env, start_response)

        except InvalidUserToken:
                self.logger.info('Invalid user token - rejecting request')
                return self._reject_request(env, start_response)
        except ServiceError as e:
            self.logger.critical('Unable to obtain admin token: %s', e)
            resp = MiniResp('Service unavailable', env)
            start_response('401 Invalid Signature', resp.headers)
            return resp.body
        except InvalidSignature as e:
            self.logger.warn('Invalid Signature: %s', e)
            resp = MiniResp('Invalid Signature', env)
            start_response('401 Invalid Signature', resp.headers)
            return resp.body
        except InvalidDateError as e:
            self.logger.warn('%s', e)
            resp = MiniResp('Invalid Header Date', env)
            start_response('401 Invalid Header Date', resp.headers)
            return resp.body
        except SignatureExpireFormatError as e:
            self.logger.warn('%s', e)
            resp = MiniResp('Invalid Header Date Format', env)
            start_response('401 Invalid Header Date Format', resp.headers)
            return resp.body
        except SignatureExpireError as e:
            self.logger.info('%s', e)
            resp = MiniResp('Signature Expire Error', env)
            start_response('401 Signature Expire Error', resp.headers)
            return resp.body
        except Exception as e:
            self.logger.warn('exception %s', e)
            resp = MiniResp('Service unavailable', env)
            start_response('500 Service Unavailable', resp.headers)
            return resp.body


    def _reject_request(self, env, start_response):
        """Redirect client to auth server.

        :param env: wsgi request environment
        :param start_response: wsgi response callback
        :returns HTTPUnauthorized http response

        """
        headers = [('WWW-Authenticate', 'Keystone uri=\'%s\'' % self.identity_uri)]
        resp = MiniResp('Authentication required', env, headers)
        start_response('401 Unauthorized', resp.headers)
        return resp.body


    def _header_to_env_var(self, key):
        """Convert header to wsgi env variable.

        :param key: http header name (ex. 'X-Auth-Token')
        :return wsgi env variable name (ex. 'HTTP_X_AUTH_TOKEN')

        """
        return 'HTTP_%s' % key.replace('-', '_').upper()

    def _remove_headers(self, env, keys):
        """Remove http headers from environment."""
        for k in keys:
            env_key = self._header_to_env_var(k)
            try:
                del env[env_key]
            except KeyError:
                pass

    def _remove_auth_headers(self, env):
        """Remove headers so a user can't fake authentication.

        :param env: wsgi request environment

        """
        auth_headers = (
            'X-Identity-Status',
            'X-Domain-Id',
            'X-Domain-Name',
            'X-Project-Id',
            'X-Project-Name',
            'X-Project-Domain-Id',
            'X-Project-Domain-Name',
            'X-User-Id',
            'X-User-Name',
            'X-User-Domain-Id',
            'X-User-Domain-Name',
            'X-Roles',
            'X-Service-Catalog',
            # Deprecated
            'X-User',
            'X-Tenant-Id',
            'X-Tenant-Name',
            'X-Tenant',
            'X-Role',
        )
        self.logger.debug('Removing headers from request environment: %s',
                       ','.join(auth_headers))
        self._remove_headers(env, auth_headers)

    def _build_user_headers(self, token_info):
        """Convert token object into headers.

        Build headers that represent authenticated user - see main
        doc info at start of file for details of headers to be defined.

        :param token_info: token object returned by keystone on authentication
        :raise InvalidUserToken when unable to parse token object

        """
        auth_ref = access.AccessInfo.factory(body=token_info)
        roles = ','.join(auth_ref.role_names)

        if _token_is_v2(token_info) and not auth_ref.project_id:
            raise InvalidUserToken('Unable to determine tenancy.')

        rval = {
            'X-Identity-Status': 'Confirmed',
            'X-Domain-Id': auth_ref.domain_id,
            'X-Domain-Name': auth_ref.domain_name,
            'X-Project-Id': auth_ref.project_id,
            'X-Project-Name': auth_ref.project_name,
            'X-Project-Domain-Id': auth_ref.project_domain_id,
            'X-Project-Domain-Name': auth_ref.project_domain_name,
            'X-User-Id': auth_ref.user_id,
            'X-User-Name': auth_ref.username,
            'X-User-Domain-Id': auth_ref.user_domain_id,
            'X-User-Domain-Name': auth_ref.user_domain_name,
            'X-Roles': roles,
            # Deprecated
            'X-User': auth_ref.username,
            'X-Tenant-Id': auth_ref.project_id,
            'X-Tenant-Name': auth_ref.project_name,
            'X-Tenant': auth_ref.project_name,
            'X-Role': roles,
            'X-AUTH-TOKEN': auth_ref.auth_token
        }

        self.logger.debug('Received request from user: %s with project_id : %s'
                          ' and roles: %s ',
                          auth_ref.user_id, auth_ref.project_id, roles)

        if  auth_ref.has_service_catalog():
            catalog = auth_ref.service_catalog.get_data()
            if _token_is_v3(token_info):
                catalog = _v3_to_v2_catalog(catalog)
            rval['X-Service-Catalog'] = json.dumps(catalog)

        return rval

    def _add_headers(self, env, headers):
        """Add http headers to environment."""
        for (k, v) in six.iteritems(headers):
            env_key = self._header_to_env_var(k)
            env[env_key] = v

    @staticmethod
    def auth_str_equal(provided, known):
        """Constant-time string comparison.

        :params provided: the first string
        :params known: the second string

        :return: True if the strings are equal.

        This function takes two strings and compares them.  It is intended to be
        used when doing a comparison for authentication purposes to help guard
        against timing attacks.  When using the function for this purpose, always
        provide the user-provided password as the first argument.  The time this
        function will take is always a factor of the length of this string.
        """
        result = 0
        p_len = len(provided)
        k_len = len(known)
        for i in six.moves.range(p_len):
            a = ord(provided[i]) if i < p_len else 0
            b = ord(known[i]) if i < k_len else 0
            result |= a ^ b
        return (p_len == k_len) & (result == 0)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def signature_auth_filter(app):
        return SignatureAuthMiddleware(app, conf)
    return signature_auth_filter

