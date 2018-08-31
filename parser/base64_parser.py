import threading, time
import dotnet
import dotnet.seamless
import System
from System.Security.Cryptography import X509Certificates
from System import Convert
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID


def getbase64Array(file):
    b64array = []
    with open(file, 'rt', encoding='utf-8', errors='ignore') as f:
        reader = csv.DictReader(f, ['base64'], dialect='csvCommaDialect')
        b64array = [str(row['base64']).strip() for row in reader]
    return b64array


class ParserThread(threading.Thread):
    def __init__(self, base64, mut):
        threading.Thread.__init__(self)
        self.__base64 = base64
        self.__mutex = mut

    def parse(self):
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

        X509list = []
        X509OIDsList = []
        oid2name = x509.oid._OID_NAMES

        X509Entity = {}
        try:
            data = Convert.FromBase64String(self.__base64)
            temp_cert = X509Certificates.X509Certificate(data)
            cert = x509.load_der_x509_certificate(bytes(temp_cert.GetRawCertData()),
                                                  default_backend())
            data = None
            X509Entity['serial'] = temp_cert.GetSerialNumberString()
            temp_cert = None
            # SubjectInfo

            X509Entity['Subject_SNILS'] = ''.join([getvalue(x.value) for x in cert.subject if (
                oid2name.get(x.oid) or get_oid(x.oid.dotted_string)) == 'SNILS'])
            X509Entity['Subject_orgRequisites'] = ''.join(
                [getvalue(x.value).replace('-', '/') for x in cert.subject if (
                    oid2name.get(x.oid) or get_oid(x.oid.dotted_string)) == 'orgRequisites'])
            requisites = X509Entity['Subject_orgRequisites'].replace('INN=', '').replace('KPP=', '')\
                .replace('OGRN=', '').replace('ИНН=', '').replace('КПП=', '').replace('ОГРН=', '')\
                .replace('ОГРНИП=', '').replace('OGRNIP', '').replace(' ', '').strip().split('/')
            X509Entity['Subject_INN'] = ''
            try:
                if len(requisites[0]) == 10 or len(requisites[0]) == 12:
                    X509Entity['Subject_INN'] = requisites[0]
            except:
                X509Entity['Subject_INN'] = ''
            if X509Entity['Subject_INN'] == '':
                X509Entity['Subject_INN'] = ''.join([getvalue(x.value) for x in cert.subject if (
                    oid2name.get(x.oid) or get_oid(x.oid.dotted_string)) == 'INN'])
            X509Entity['Subject_KPP'] = ''
            try:
                if len(requisites[1]) == 9:
                    X509Entity['Subject_KPP'] = requisites[1]
            except:
                X509Entity['Subject_KPP'] = ''

            X509Entity['Subject_OGRN'] = ''
            try:
                if len(requisites[2]) == 13 or len(requisites[2]) == 15:
                    X509Entity['Subject_OGRN'] = requisites[2]
            except:
                X509Entity['Subject_OGRN'] = ''
            if X509Entity['Subject_OGRN'] == '':
                X509Entity['Subject_OGRN'] = ''.join([getvalue(x.value) for x in cert.subject if (
                    oid2name.get(x.oid) or get_oid(x.oid.dotted_string)) == 'OGRN'])

            X509Entity['Subject_CommonName'] = ''.join([getvalue(x.value) for x in cert.subject if (
                oid2name.get(x.oid) or get_oid(x.oid.dotted_string)) == 'commonName'])
            X509Entity['Subject_Department'] = '; '.join(
                [getvalue(x.value) for x in cert.subject if (
                    oid2name.get(x.oid) or get_oid(
                        x.oid.dotted_string)) == 'organizationalUnitName'])
            X509Entity['Subject_region'] = ''.join([getvalue(x.value) for x in cert.subject if (
                oid2name.get(x.oid) or get_oid(x.oid.dotted_string)) == 'stateOrProvinceName'])
            X509Entity['Subject_city'] = ''.join([getvalue(x.value) for x in cert.subject if (
                oid2name.get(x.oid) or get_oid(x.oid.dotted_string)) == 'localityName'])
            X509Entity['Subject_streetAddress'] = ''.join(
                [getvalue(x.value) for x in cert.subject if (
                    oid2name.get(x.oid) or get_oid(x.oid.dotted_string)) == 'streetAddress'])

            X509Entity['Subject_email'] = ''.join([getvalue(x.value) for x in cert.subject if (
                oid2name.get(x.oid) or get_oid(x.oid.dotted_string)) == 'emailAddress'])
            X509Entity['Subject_User'] = ''.join([getvalue(x.value) for x in cert.subject if (
                oid2name.get(x.oid) or get_oid(x.oid.dotted_string)) == 'surname'])
            X509Entity['Subject_User'] += ' ' + ''.join([getvalue(x.value) for x in cert.subject if
                                                         (oid2name.get(x.oid) or get_oid(
                                                             x.oid.dotted_string)) == 'givenName'])
            X509Entity['Subject_UserPost'] = ''.join([getvalue(x.value) for x in cert.subject if (
                oid2name.get(x.oid) or get_oid(x.oid.dotted_string)) == 'title'])

            X509Entity['Thumb'] = str(cert.fingerprint(hashes.SHA1()).hex().upper())
            # X509Entity['serial'] = str(hex(cert.serial_number))
            X509Entity['ValidFrom'] = cert.not_valid_before.strftime('%Y-%m-%d')
            X509Entity['ValidTo'] = cert.not_valid_after.strftime('%Y-%m-%d')

            # IssuerInfo
            X509Entity['Issuer_CN'] = ''.join([getvalue(x.value) for x in cert.issuer if (
                oid2name.get(x.oid) or get_oid(x.oid.dotted_string)) == 'commonName'])

            X509Entity['sign'] = self.__base64
            try:
                for x in cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value:
                    X509OID = {}
                    X509OID['Thumb'] = X509Entity['Thumb']
                    X509OID['oid'] = x.dotted_string
                    X509OID['value'] = ''
                    X509OID['type'] = 'extensions'
                    X509OIDsList.append(X509OID)
            except:
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

        except Exception as e:
            print('error sign!')
            pass

        return X509list, X509OIDsList

    def run(self):
        X509list, X509OIDsList = self.parse()
        if X509list is not None:
            self.__mutex.acquire()
            with open('certificates.csv', 'at', encoding='cp1251', errors='ignore') as file:
                writer = csv.DictWriter(file,
                                        ['Issuer_CN', 'Subject_INN', 'Subject_KPP', 'Subject_OGRN', 'Subject_SNILS',
                                         'Subject_orgRequisites', 'Thumb', 'serial', 'ValidFrom', 'ValidTo',
                                         'Subject_CommonName', 'Subject_User', 'Subject_Department',
                                         'Subject_UserPost', 'Subject_email', 'Subject_region', 'Subject_city',
                                         'Subject_streetAddress', 'sign'],
                                        dialect='csvCommaDialect')
                writer.writerows(X509list)

            with open('certificatesOIDs.csv', 'at', encoding='cp1251', errors='ignore') as file:
                writer = csv.DictWriter(file, ['Thumb', 'oid', 'type', 'value'],
                                        dialect='csvCommaDialect')
                writer.writerows(X509OIDsList)
            self.__mutex.release()


def createthreadparserzip(count, zip_files):
    mutex = threading.Lock()
    listthrd = []
    while len(zip_files) != 0:
        if threading.active_count() <= count:
            file = zip_files.pop()
            parserthrd = ParserThread(file, mutex)
            parserthrd.start()
            listthrd.append(parserthrd)
        else:
            time.sleep(0.1)
    for thrd in listthrd:
        thrd.join()
    return None


t0 = time.time()
sign_list = getbase64Array('base64_certs.csv')
# first argument - count of threads, second argument - list of base64 strings
createthreadparserzip(5, sign_list)
t = time.time() - t0
print('Total time (sec.): %fs' % t)
with open('timelog.log', 'at', encoding='cp1251', errors='ignore') as file:
    file.write('Total time (sec.): %fs' % t + '\n')
    file.flush()
