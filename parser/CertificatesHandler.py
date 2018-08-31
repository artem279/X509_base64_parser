import threading
from threading import Thread
from queue import Queue
import dotnet
import dotnet.seamless
import System
from System.Security.Cryptography import X509Certificates
from System import Convert
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID


class Task(Thread):
    def __init__(self, tasks):
        Thread.__init__(self)
        self.tasks = tasks
        self.daemon = True
        self.start()

    def run(self):
        while True:
            func, args, kwargs = self.tasks.get()
            try:
                func(*args, **kwargs)
            except Exception as e:
                print(e)
            finally:
                self.tasks.task_done()


class ThreadPool:
    """Pool of threads consuming tasks from a queue"""

    def __init__(self, num_threads):
        self.tasks = Queue(num_threads)
        for _ in range(num_threads):
            Task(self.tasks)

    def add_task(self, func, *args, **kwargs):
        """Add a task to the queue"""
        self.tasks.put((func, args, kwargs))

    def wait_completion(self):
        """block until all tasks are done"""
        self.tasks.join()


def getvalue(tag):
    value = ''
    try:
        value = tag.replace('\n', '').replace('\r', '').replace('\t', '').replace('|', '/') \
            .replace('"', '').replace('  ', '').replace('NULL', '').replace(';', ',')
    except:
        value = ''
    return value


def get_oid(name):
    text = ''
    if name == '1.2.643.3.131.1.1':
        text = 'INN'
    elif name == '1.2.643.100.1':
        text = 'OGRN'
    elif name == '1.2.643.100.3':
        text = 'SNILS'
    elif name == '1.2.840.113549.1.9.2':
        text = 'orgRequisites'
    else:
        text = name
    return text


def parse(**kwargs):
    # Объявляем списки для хранения словарей и пространство OID-имён
    X509list = []
    X509OIDsList = []
    oid2name = x509.oid._OID_NAMES

    # Объявляем словарь-контейнер для хранения данных сертификата
    X509Entity = {}

    try:
        # Читаем файл и загружаем в массив байтов
        data = Convert.FromBase64String(kwargs['sign'])
        data = X509Certificates.X509Certificate(data)
        X509Entity['serial'] = data.GetSerialNumberString()
        X509Entity['sign'] = kwargs['sign']
        cert = x509.load_der_x509_certificate(bytes(data.GetRawCertData()), default_backend())
        data = None

        # SubjectInfo

        X509Entity['Subject_SNILS'] = ''.join(
            [getvalue(x.value) for x in cert.subject if
             (oid2name.get(x.oid) or get_oid(x.oid.dotted_string)) == 'SNILS'])
        X509Entity['Subject_orgRequisites'] = ''.join([getvalue(x.value).replace('-', '/') for x in cert.subject if (
                oid2name.get(x.oid) or get_oid(x.oid.dotted_string)) == 'orgRequisites'])
        requisites = X509Entity['Subject_orgRequisites'].replace('INN=', '') \
            .replace('KPP=', '').replace('OGRN=', '').replace('ИНН=', '').replace('КПП=', '') \
            .replace('ОГРН=', '').replace('ОГРНИП=', '').replace('OGRNIP', '') \
            .replace(' ', '').strip().split('/')
        X509Entity['Subject_INN'] = ''
        try:
            if len(requisites[0]) == 10 or len(requisites[0]) == 12:
                X509Entity['Subject_INN'] = requisites[0]
        except Exception as exc:
            X509Entity['Subject_INN'] = ''

        if X509Entity['Subject_INN'] == '':
            X509Entity['Subject_INN'] = ''.join(
                [getvalue(x.value) for x in cert.subject if
                 (oid2name.get(x.oid) or get_oid(x.oid.dotted_string)) == 'INN'])

        X509Entity['Subject_KPP'] = ''
        try:
            if len(requisites[1]) == 9:
                X509Entity['Subject_KPP'] = requisites[1]
        except Exception as exc:
            X509Entity['Subject_KPP'] = ''

        X509Entity['Subject_OGRN'] = ''
        try:
            if len(requisites[2]) == 13 or len(requisites[2]) == 15:
                X509Entity['Subject_OGRN'] = requisites[2]
        except Exception as exc:
            X509Entity['Subject_OGRN'] = ''

        if X509Entity['Subject_OGRN'] == '':
            X509Entity['Subject_OGRN'] = ''.join([getvalue(x.value) for x in cert.subject if
                                                  (oid2name.get(x.oid) or get_oid(x.oid.dotted_string)) == 'OGRN'])

        X509Entity['Subject_CommonName'] = ''.join([getvalue(x.value) for x in cert.subject if
                                                    (oid2name.get(x.oid) or get_oid(
                                                        x.oid.dotted_string)) == 'commonName'])

        department = []
        for x in cert.subject:
            if (oid2name.get(x.oid) or get_oid(x.oid.dotted_string)) == 'organizationalUnitName':
                if getvalue(x.value) not in department:
                    department.append(getvalue(x.value))
        X509Entity['Subject_Department'] = '; '.join(department)

        X509Entity['Subject_region'] = ''.join([getvalue(x.value) for x in cert.subject if (
                oid2name.get(x.oid) or get_oid(x.oid.dotted_string)) == 'stateOrProvinceName'])
        X509Entity['Subject_city'] = ''.join([getvalue(x.value) for x in cert.subject if
                                              (oid2name.get(x.oid) or get_oid(x.oid.dotted_string)) == 'localityName'])
        X509Entity['Subject_streetAddress'] = ''.join([getvalue(x.value) for x in cert.subject if (
                oid2name.get(x.oid) or get_oid(x.oid.dotted_string)) == 'streetAddress'])

        X509Entity['Subject_email'] = ''.join([getvalue(x.value) for x in cert.subject if
                                               (oid2name.get(x.oid) or get_oid(x.oid.dotted_string)) == 'emailAddress'])
        X509Entity['Subject_User'] = ''.join(
            [getvalue(x.value) for x in cert.subject if
             (oid2name.get(x.oid) or get_oid(x.oid.dotted_string)) == 'surname'])
        X509Entity['Subject_User'] += ' ' + ''.join([getvalue(x.value) for x in cert.subject if
                                                     (oid2name.get(x.oid) or get_oid(
                                                         x.oid.dotted_string)) == 'givenName'])
        X509Entity['Subject_UserPost'] = ''.join(
            [getvalue(x.value) for x in cert.subject if
             (oid2name.get(x.oid) or get_oid(x.oid.dotted_string)) == 'title'])

        X509Entity['Thumb'] = str(cert.fingerprint(hashes.SHA1()).hex().upper())
        X509Entity['ValidFrom'] = cert.not_valid_before.strftime('%Y-%m-%d')
        X509Entity['ValidTo'] = cert.not_valid_after.strftime('%Y-%m-%d')

        # IssuerInfo
        X509Entity['Issuer_CN'] = ''.join([getvalue(x.value) for x in cert.issuer if
                                           (oid2name.get(x.oid) or get_oid(x.oid.dotted_string)) == 'commonName'])



        try:
            for x in cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value:
                X509OID = {}
                X509OID['Thumb'] = X509Entity['Thumb']
                X509OID['oid'] = x.dotted_string
                X509OID['value'] = ''
                X509OID['type'] = 'extensions'
                X509OIDsList.append(X509OID)
        except Exception as exc:
            pass

        for x in cert.subject.rdns:
            for i in x:
                X509OID = {}
                X509OID['Thumb'] = X509Entity['Thumb']
                X509OID['oid'] = i.oid.dotted_string
                X509OID['value'] = (getvalue(i.value) or '')
                X509OID['type'] = 'subject'
                X509OIDsList.append(X509OID)

        for x in cert.issuer.rdns:
            for i in x:
                X509OID = {}
                X509OID['Thumb'] = X509Entity['Thumb']
                X509OID['oid'] = i.oid.dotted_string
                X509OID['value'] = (getvalue(i.value) or '')
                X509OID['type'] = 'issuer'
                X509OIDsList.append(X509OID)

        X509list.append(X509Entity)
        print(X509Entity['Thumb'])
    except Exception as exc:
        pass

    if len(X509list) > 0:
        kwargs['mutex'].acquire()
        kwargs['certificates'].extend(X509list)
        kwargs['oids'].extend(X509OIDsList)
        kwargs['mutex'].release()


def createthreadparser(thread_count, signs):
    mutex = threading.Lock()
    pool = ThreadPool(int(thread_count))
    X509list = []
    X509OIDsList = []
    while len(signs) != 0:
        sign = signs.pop()
        pool.add_task(parse, sign=sign, mutex=mutex, certificates=X509list, oids=X509OIDsList)
    pool.wait_completion()

    return X509list, X509OIDsList

