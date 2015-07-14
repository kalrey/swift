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
"""
This middleware is for quota management: when user's requests in 1 minute greater than
a config size,then refused
"""

from swift.common.swob import Response, wsgify
from gettext import gettext as _
import time
from swift.common.utils import cache_from_env, get_logger
from swift.proxy.controllers.base import get_account_info


class QuotaCheckMiddleware(object):
    def __init__(self, app, conf, logger=None):
        self.app = app
        self.conf = conf
        self.memcache_client = None

        if logger:
            self.logger = logger
        else:
            self.logger = get_logger(conf, log_route="iops")


    @wsgify
    def __call__(self, req):
        self.memcache_client = cache_from_env(req.environ)

        version, account, container, obj = req.split_path(1, 4, True)
        ps = self.update_cache(req, account)

        if ps < 0:
            return self.app

        if self.incr_and_check(req, account, ps):
            return self.app
        else:
            self.logger.error(_("Return 413 because of IOPS quota too large: %s"),
                              account)

            return Response(request=req, status=413, body="IOPS Quota too large",
                            context_type="text/plain")

    def update_cache(self, req, account):
        in_write = False

        if req.method in ("POST", "PUT", "DELETE"):
            ps = req.headers.get('X-Account-Meta-Ips')
            key = "(ips/%s)" % account
            in_write = True
        else:
            ps = req.headers.get('X-Account-Meta-Ops')
            key = "(ops/%s)" % account

        ps = int(ps) if ps else -1

        cache_ps = self.memcache_client.get(key)
        cache_ps = int(cache_ps) if cache_ps else -1
        if cache_ps < 0:
            if ps < 0:
                account_info = get_account_info(req.environ, self.app)
                if not account_info or not account_info['meta']:
                    self.memcache_client.set(key, -1, serialize=False, time=300)
                    return -1, -1

                if in_write:
                    ps = int(account_info['meta'].get('ips', -1))
                else:
                    ps = int(account_info['meta'].get('ops', -1))

            self.memcache_client.set(key, ps, serialize=False, time=300)
            return ps
        else:
            return cache_ps

    def incr_and_check(self, request, account, ps):
        now = time.time()

        ips_key = "(%s/ips/%s)" % (account, now)
        ops_key = "(%s/ops/%s)" % (account, now)

        if request.method in ("POST", "PUT", "DELETE"):
            ret = self.memcache_client.incr(ips_key, timeout=10)
            if ret > ps:
                return False

        if request.method in ("GET"):
            ret = self.memcache_client.incr(ops_key, timeout=10)
            if ret > ps:
                return False

        return True


def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def quota_filter(app):
        return QuotaCheckMiddleware(app, conf)
    return quota_filter