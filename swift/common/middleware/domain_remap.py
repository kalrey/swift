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
Domain Remap Middleware

Middleware that translates container and account parts of a domain to
path parameters that the proxy server understands.

container.account.storageurl/object gets translated to
container.account.storageurl/path_root/account/container/object

account.storageurl/path_root/container/object gets translated to
account.storageurl/path_root/account/container/object

Browsers can convert a host header to lowercase, so check that reseller
prefix on the account is the correct case. This is done by comparing the
items in the reseller_prefixes config option to the found prefix. If they
match except for case, the item from reseller_prefixes will be used
instead of the found reseller prefix. The reseller_prefixes list is
exclusive. If defined, any request with an account prefix not in that list
will be ignored by this middleware. reseller_prefixes defaults to 'AUTH'.

Note that this middleware requires that container names and account names
(except as described above) must be DNS-compatible. This means that the
account name created in the system and the containers created by users
cannot exceed 63 characters or have UTF-8 characters. These are
restrictions over and above what swift requires and are not explicitly
checked. Simply put, the this middleware will do a best-effort attempt to
derive account and container names from elements in the domain name and
put those derived values into the URL path (leaving the Host header
unchanged).

Also note that using container sync with remapped domain names is not
advised. With container sync, you should use the true storage end points as
sync destinations.
"""

from swift.common.swob import Request, HTTPBadRequest
from swift.common.utils import get_logger


class DomainRemapMiddleware(object):
    """
    Domain Remap Middleware

    See above for a full description.

    :param app: The next WSGI filter or app in the paste.deploy
                chain.
    :param conf: The configuration dict for the middleware.
    """

    def __init__(self, app, conf, logger=None):
        self.app = app
        self.storage_domains = conf.get('storage_domain', 'example.com')
        if self.storage_domains:
            self.storage_domains = self.storage_domains.split(',')
        self.storage_domains = ['.' + x if x[0] != '.' else x for x in self.storage_domains]
        self.path_root = conf.get('path_root', 'v1').strip('/')
        if logger:
            self.logger = logger
        else:
            self.logger = get_logger(conf, log_route="domain_remap")


    def __call__(self, env, start_response):
        if not self.storage_domains:
            return self.app(env, start_response)
        if 'HTTP_HOST' in env:
            given_domain = env['HTTP_HOST']
        else:
            given_domain = env['SERVER_NAME']
        port = ''
        if ':' in given_domain:
            given_domain, port = given_domain.rsplit(':', 1)
        for storage_domain in self.storage_domains:
            if given_domain.endswith(storage_domain):
                parts_to_parse = given_domain[:-len(storage_domain)]
                parts_to_parse = parts_to_parse.strip('.').split('.')
                len_parts_to_parse = len(parts_to_parse)
                if len_parts_to_parse == 2:
                    container, account = parts_to_parse
                elif len_parts_to_parse == 1:
                    container, account = None, parts_to_parse[0]
                else:
                    resp = HTTPBadRequest(request=Request(env),
                                          body='Bad domain in host header',
                                          content_type='text/plain')
                    return resp(env, start_response)
                path = env['PATH_INFO'].strip('/')
                new_path_parts = ['', self.path_root, account]
                if container:
                    new_path_parts.append(container)
                if path.startswith(self.path_root):
                    path = path[len(self.path_root):].lstrip('/')
                if path:
                    new_path_parts.append(path)
                new_path = '/'.join(new_path_parts)
                env['PATH_INFO'] = new_path
                break
        return self.app(env, start_response)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def domain_filter(app):
        return DomainRemapMiddleware(app, conf)
    return domain_filter
