__author__ = 'byliu'

import os
from hashlib import md5
from swift.common.utils import get_logger
from swift.common.swob import Request, HTTPPreconditionFailed


MAIN_KEY_MD5 = 'X-Object-Sse-C-Keymd5'
MAIN_KEY = 'X-Object-Sse-C-Key'
MAIN_KEY_MD5_NEW = 'X-Object-Sse-C-New-Keymd5'
MAIN_KEY_NEW = 'X-Object-Sse-C-New-Key'


class GenerageEnckeyMiddleware(object):

    def __init__(self, app, conf):
        self.app = app
        self.conf = conf
        self.logger = get_logger(self.conf, log_route='generage_enckey')

    def generate_enc_key(self):
        """
        Generate a unique, random key for encrypting this file.
        A new key will be generated each time the file is modified.
        """
        rand_key = md5(os.urandom(32)).hexdigest()
        return rand_key

    def is2encrypt(self, req):
        if MAIN_KEY in req.headers and MAIN_KEY_MD5 in req.headers:
            return True
        return False

    def check_main_key(self, req):
        main_key = req.headers[MAIN_KEY]
        main_key_md5 = req.headers[MAIN_KEY_MD5]
        if main_key_md5 == md5(main_key).hexdigest():
            return True
        return False

    def is2change_mainkey(self, req):
        if self.is2encrypt(req):
            if MAIN_KEY_NEW in req.headers and MAIN_KEY_MD5_NEW in req.headers:
                return True
        return False

    def check_new_main_key(self, req):
        main_key_new = req.headers[MAIN_KEY_NEW]
        main_key_md5_new = req.headers[MAIN_KEY_MD5_NEW]
        if main_key_md5_new == md5(main_key_new).hexdigest():
            return True
        return False

    def __call__(self, env, start_response):
        req = Request(env)
        if req.method == 'PUT':
            if self.is2encrypt(req):
                if self.check_main_key(req):
                    obj_enc_key = self.generate_enc_key()
                    env['HTTP_OBJ_ENC_KEY'] = obj_enc_key
                else:
                    return HTTPPreconditionFailed(
                        request=req,
                        body=('key and keymd5 do not match')
                    )(env, start_response)
        elif req.method == 'GET':
            if self.is2encrypt(req):
                if self.check_main_key(req):
                    pass
                else:
                    return HTTPPreconditionFailed(
                        request=req,
                        body=('key and keymd5 do not match')
                    )(env, start_response)
        elif req.method == 'POST':
            if self.is2encrypt(req):
                if self.check_main_key(req):
                    if 'X-Object-Sse-C-Enable' in req.headers:
                        obj_enc_key = self.generate_enc_key()
                        env['HTTP_OBJ_ENC_KEY'] = obj_enc_key
                    if self.is2change_mainkey(req):
                        if self.check_new_main_key(req):
                            obj_enc_key = self.generate_enc_key()
                            env['HTTP_OBJ_ENC_KEY'] = obj_enc_key
                        else:
                            return HTTPPreconditionFailed(
                                request=req,
                                body=('new key and new keymd5 do not match')
                            )(env, start_response)
                else:
                    return HTTPPreconditionFailed(
                        request=req,
                        body=('key and keymd5 do not match')
                    )(env, start_response)

        return self.app(env, start_response)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def generate_enckey_filter(app):
        return GenerageEnckeyMiddleware(app, conf)
    return generate_enckey_filter
