__author__ = 'kalrey'


from swift.common.utils import split_path
import logging
import re
from string import lower


def path_lower(matcher):
    group = matcher.groupdict()
    entire = matcher.group(0)
    for key, value in group.items():
        if value:
            entire = entire.replace(value, lower(value))
    return entire


class PathLower(object):

    def __init__(self, app, conf):
        self.LOG = logging.getLogger(conf.get('log_name', __name__))
        self.LOG.info('Starting UrlReduce middleware')
        self.app = app
        self.conf = conf
        self.path_root = conf.get('path_root', 'v1').strip('/')
        self.regex = '^/' + self.path_root + '/(?P<Account>[A-Za-z\-_\d]+)(?:/(?P<Container>[A-Za-z\-_\d]+)){0,1}'

    def __call__(self, environ, start_response):
        environ['PATH_INFO'] = re.sub(self.regex, path_lower, environ['PATH_INFO'], flags=re.S)
        return self.app(environ, start_response)


def filter_factory(global_conf, **local_conf):
    conf = global_conf
    conf.update(local_conf)

    def path_filter(app):
        return PathLower(app, conf)
    return path_filter
