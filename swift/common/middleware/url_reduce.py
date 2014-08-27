__author__ = 'kalrey'
from swift.common.utils import split_path
from webob import Request
import logging
import re

STRING_REGEX = '^(?:(?P<Container>[A-Za-z\-_\d]+)\.){0,1}(?P<Account>[A-Za-z\-_\d]+)' \
               '\.(?:hf|HF|gz|GZ|bj|BJ)\.'

class UrlReduce(object):

    def __init__(self, app, conf):
        self.LOG = logging.getLogger(conf.get('log_name', __name__))
        self.LOG.info('Starting UrlReduce middleware')
        self.app = app
        self.conf = conf
        self.prefix = conf.get('prefix', 'storage')
        self.host = conf.get('host', 'dn.openstorage.cn')
        

    def __call__(self, environ, start_response):
        pattern = STRING_REGEX + self.host + '$'
        matcher = re.match(pattern, environ['HTTP_HOST'])
        if matcher:
            container = matcher.group('Container')
            account = matcher.group('Account')
            environ['HTTP_HOST'] = self.host
            path_info = environ['PATH_INFO']
            if container:
                environ['PATH_INFO'] = '/v1/' + account + '/' + container + path_info
            else:
                environ['PATH_INFO'] = '/v1/' + account + '/' + path_info
        req = Request(environ)
        url1, url2 = split_path(environ['PATH_INFO'], 1, 2, True)
        if url1 == self.prefix and url2:
            environ['PATH_INFO'] = '/' + url2
        return self.app(environ, start_response)


def filter_factory(global_conf, **local_conf):
    conf = global_conf
    conf.update(local_conf)

    def url_reduce(app):
        return UrlReduce(app, conf)
    return url_reduce