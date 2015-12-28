#!/usr/bin/env python
# coding: utf8
""" Сервер авторизации """

from crypt import crypt
from cgi import escape
# from cgi import parse_qs  # deprecated
from urlparse import parse_qs, urlparse
import logging
import os
import sys
import ipaddress
import time
import pickle
from uuid import uuid4
from hashlib import md5
from xml.etree import cElementTree as etree
import yaml
import paramiko


FMT = '[%(asctime)-12s] %(clientip)-15s %(user)-10s %(levelname)-7s %(message)s'
MGRLIST = ('ispmgr', 'billmgr', 'vmmgr', 'vemgr', 'dnsmgr', 'ipmgr', 'dcimgr')
MGRCTL5 = '/usr/local/mgr5/sbin/mgrctl'
# Время жизни сессии. Чтобы при получении доступа к компу, так сразу не
# ткнули. Паранойя, конечно. Но мало ли. В couchdb также делается с basicauth.
SESSION_LIFETIME = 60 * 10
SESSION_PATH = os.path.join(os.getcwd(), '.sessions')

try:
    with open('config.yml', 'r') as conffile:
        CFG = yaml.load(conffile)
except IOError:
    sys.stderr.write('Can not open config.yml')
    raise

USERS = CFG.get('users', {})

if CFG.get('logfile', ''):
    LOGFILE = open(CFG.get('logfile'), 'a+')
else:
    LOGFILE = None

if CFG.get('keyfile') and os.path.exists(CFG.get('keyfile')):
    KEYFILE = CFG.get('keyfile')
else:
    KEYFILE = None


def check_auth(username, password):
    """
    Проверка пользователя
    """
    users = USERS
    cryptedpassword = users.get(username, '')
    return username in users and crypt(password, cryptedpassword) == cryptedpassword


class LoggerWrapper(object):
    """
    Враппер для логгера, чтобы дописывал туда IP адрес и логин
    """
    def __init__(self, request):
        self.request = request
        self.logger = logging.getLogger('Request')
# this code for coloredlogs
#        coloredlogs.install(
#            level=logging.INFO,
#            logger=self.logger,
#            fmt=FMT,  # for coloredlogs.install
#            isatty=True,
#            stream=LOGFILE
#        )
# end for coloredlogs
# this code without coloredlogs
        handler = logging.StreamHandler(stream=LOGFILE)
        formatter = logging.Formatter(FMT)
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
# end without coloredlogs

    def __getattr__(self, attr):
        def wrapper(*args, **kwargs):
            """
            Добавим ко всем функциям логгирования
            добавление IP и пользователя
            """
            assert attr in ('info', 'warn', 'debug', 'error', 'exception', 'warinig', 'critical')
            d = {}
            env = self.request.environ
            d['clientip'] = env.get('REMOTE_ADDR', '0.0.0.0')
            d['user'] = env.get('REMOTE_USER', 'anonymous')
            if 'env' in kwargs:
                del kwargs['env']
            kwargs['extra'] = d
            return getattr(self.logger, attr)(*args, **kwargs)
        return wrapper


class GoServer(object):
    """
    Класс для работы с панельками
    """
    def __init__(self):
        self.environ = {}
        self.logger = LoggerWrapper(self)
        self.authuser = None
        self.host = None
        self.__ssh_client = None

    def __enter__(self):
        return self

    @property
    def ssh_client(self):
        """
        Если ssh сесссии не было, то создаём её.
        Заделка на будущее, Всё равно копипаст
        """
        if not (self.__ssh_client and \
                        self.__ssh_client.get_transport() and \
                        self.__ssh_client.get_transport().active
                ):
            self.__ssh_client = self.get_connection()
        return self.__ssh_client

    def get_connection(self):
        """
        Создаём ssh сессию
        """
        assert self.host is not None
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.logger.info('Connecting to %s using keyfile %s' % (self.host, KEYFILE))
        client.connect(self.host, username='root', key_filename=KEYFILE)
        return client

    def bad_auth(self):
        """
        Требуем авторизацию.
        """
        headers = [
            ('WWW-Authenticate', 'Basic realm=Restricted'),
        ]
        self.start_response('401', headers)
        return ['Auth needed']

    def require_auth(self):
        """
        Если есть basic-auth хедер, и там корректный пароль, то True
        """
        auth = self.environ.get('HTTP_AUTHORIZATION')
        if auth:
            scheme, data = auth.split(None, 1)
            assert scheme.lower() == 'basic'
            username, password = data.decode('base64').split(':', 1)
            if check_auth(username, password):
                self.environ['REMOTE_USER'] = username
                self.authuser = username
                del self.environ['HTTP_AUTHORIZATION']
                return not self.session_expired()
            self.logger.warn('Bad auth: %s, %s' % (username, password))
        return False

    def print_form(self):
        """
        Напечатать форму для ввода URL
        """
        response = '<html><head><meta http-equiv="content-type" content="text/html; charset=utf-8" />'
        response += '</head><body>'
        response += '<p>Hello %s</p>' % self.authuser
        response += '<form method="GET">'
        response += '<label for="url">Enter some manager URL where You want to go&nbsp;</label>'
        response += '<input id="url" name="url" type="text" placeholder="Enter URL here"/>'
        response += '<input type="submit" value="go" />'
        response += '</form></body></html>\n'
        self.start_response('200 OK', [('Content-type', 'text/html; charset=utf8')])
        return [response]

    def bad_param(self, param_name, param_value=''):
        """
        Сообщение об ошибке в параметрах запроса
        """
        self.start_response('400', [('Content-type', 'text/plain; charset=utf8')])
        return b'Bad parameter %s: %s\n' % (param_name, param_value)

    def internal_error(self, text=''):
        """
        Ошибка 500
        @param text:
        @return:
        """
        self.start_response('500', [('Content-type', 'text/plain; charset=utf8')])
        return [text]

    def make_redirect(self, auth_code):
        """
        Создать редирект на манагер со всеми параметрами.
        """
        redirect_base = self.mgrurl.geturl().replace('?' + self.mgrurl.query,'')
        user = 'root'
        redirect_params = '?func=auth&username=%s&key=%s&checkcookie=no' % (user, auth_code)
        redirect_url = redirect_base + redirect_params
        self.start_response('302 Found', [('Location', redirect_url)])
        self.logger.info('Make redirect: %s' % redirect_url)
        return []

    def create_auth_code(self, mgr):
        """
        Авторизоваться по SSH на сервере и сгенерить код авторизации
        """
        user = 'root' # пока всегда root
        key = uuid4().get_hex()
        self.logger.info('Request auth code')
        # Команда для авторизации
        # see: http://doc.ispsystem.ru/index.php/Взаимодействие_через_API
        cmd = '%s -m %s -o xml session.newkey key=%s user=%s' % (MGRCTL5, mgr, key, user)
        _, out, err = self.ssh_client.exec_command(cmd)
        err_text = err.read()
        if err_text:
            # Если что-то в stderr, то даже не пытаемся смотреть дальше
            raise Exception(err_text)
        else:
            xmldoc = etree.parse(out).getroot()
            if xmldoc.find('ok') is not None:
                # Выход здесь
                return key
            elif xmldoc.find('error') is not None:
                raise Exception(xmldoc.find('error').text)
            else:
                raise Exception('Unknown error on xml parse')

    def check_network(self):
        remote_addr = self.environ.get('REMOTE_ADDR')
        for network in CFG.get('networks'):
            if ipaddress.ip_address(unicode(remote_addr)) in ipaddress.ip_network(unicode(network)):
                return True
        return False

    def bad_network(self):
        self.start_response('403 Forbidden', [])
        return [b'Acces denied. Wrong IP\n']

    def session_expired(self):
        """
        Проверить сессию. Если её нету, или срок не вышел, то вернуть False.
        Иначе True
        Да, здесь могут быть race conditions, если один пользователь в двух вкладках
        будет авторизовываться одновременно. Но это проблемы этого пользователя.
        """
        remote_addr = self.environ.get('REMOTE_ADDR')
        hash = md5(self.authuser).hexdigest()
        spath = os.path.join(SESSION_PATH, hash)
        if os.path.isfile(spath):  # файл сессии есть
            try:
                sfile = open(spath, 'r')
                sdata = pickle.load(sfile)  # в pickle лежит dict
                sfile.close()
                expire = sdata.get('expire')
                session_addr = sdata.get('addr')
                if md5(remote_addr).hexdigest() != session_addr:
                    os.remove(spath)
                    self.logger.info('Session from another IP')
                    return True
                if int(time.time()) > int(expire):
                    os.remove(spath)
                    self.logger.info('Session expired')
                    return True
            except:
                # ошибки трактуются как истёкшая сессия
                os.remove(spath)
                return True
        else:  # файла сессии нету
            self.logger.info('Session not exists')
            try:
                sdata = {
                    'addr': md5(remote_addr).hexdigest(),
                    'expire': int(time.time()) + SESSION_LIFETIME,
                }
                if not os.path.exists(SESSION_PATH):
                    os.mkdir(SESSION_PATH, 0o700)
                sfile = os.fdopen(os.open(spath, os.O_WRONLY | os.O_CREAT, 0600), 'w')
                pickle.dump(sdata, sfile) # в pickle лежит dict
                sfile.close()
            except Exception as err:
                # ошибки записи игнорируются в работе, но отмечаются в лог
                self.logger.exception(err)
        # если не вернули true, значит с сессией всё в порядке
        self.logger.info('Session is ok')
        return False

    def __call__(self, environ, start_response):
        """
        WSGI метод. Зовётся при поступлении запроса
        """
        self.environ = environ
        self.start_response = start_response
        if not self.check_network():
            return self.bad_network()
        if not self.require_auth():
            return self.bad_auth()
        parameters = parse_qs(environ.get('QUERY_STRING', ''))

        if 'url' in parameters:
            urlparam = escape(parameters.get('url')[0])
            self.mgrurl = urlparse(urlparam)
            self.logger.info('Request: %s' % self.mgrurl.geturl())

            mgr = self.mgrurl.path.replace('/','')
            self.host = self.mgrurl.hostname
            if mgr not in MGRLIST:
                # Если какой-то неправильный путь в URL, то bad request
                return self.bad_param('manager', mgr)
            try:
                auth_code = self.create_auth_code(mgr)
                self.logger.info('Auth code recieved')
                return self.make_redirect(auth_code)
            except Exception as err:
                # Что-то пошло не так
                self.logger.exception(err)
                return self.internal_error('Can not create auth code')
        else:
            self.logger.info('Empty url. Writing form')
            return self.print_form()

    def close_connection(self):
        if self.__ssh_client:
            self.logger.info('Closing shh connection to %s' % self.host)
            self.__ssh_client.close()

    def __exit__(self, *args):
        self.close_connection()


def myapp(environ, start_response):
    with GoServer() as request:
        return request(environ, start_response)
