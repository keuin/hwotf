# HIT Senseless WLAN
# ------------------
# Version: 1.2.1-beta
# Author:  Keuin
# GitHub:  https://github.com/keuin

# TODO:
#   1. Encrypt the password while transmitting.
#   2. Handle the response in a more informative way.

try:
    import requests
    import gzip
    import re
    import json
    import os
    import sys
    import logging
except ModuleNotFoundError as e:
    print(f'Some essential modules are missing. Please run "pip install {e.name}" and try again.')
    exit()

CONFIG_FILE = 'hit.senseless.json'
LOG_FILE = 'hit.senseless.log'


def generate_204():
    return requests.get('http://www.gstatic.com/generate_204')


def has_internet(req_204=None) -> bool:
    """
    Check if the LAN has internet connection.
    Note that an IOError will be thrown if no LAN or login server is available.
    :return: True if connected to internet, False if need authentication.
    """
    r = req_204 or generate_204()
    return r.status_code == 204


class LoginException(Exception):

    def __init__(self, *args: object) -> None:
        super().__init__(*args)


class BadProbeResponseException(LoginException):

    def __init__(self, *args: object) -> None:
        super().__init__(*args)


class GenericBadResponseException(LoginException):

    def __init__(self, *args: object) -> None:
        super().__init__(*args)


class RuiJie:

    @staticmethod
    def magic_decompress_gzip(data: bytes) -> bytes:
        try:
            return gzip.decompress(data)
        except ValueError:
            return data


class LoginHelper:
    _session = requests.session()
    _login_root_url = ''
    _user_index = ''

    def __init__(self, user_agent: str = None):
        if not user_agent:
            user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)'
        self._session = requests.session()
        self._session.headers['User-Agent'] = user_agent

    def login(self, username: str, password: str, auth_server_host: str = None) -> bool:
        # probe Internet and auth server

        # detect the Internet connection
        r = generate_204()
        if has_internet(r):
            return True

        # get the auth page address
        try:
            url = re.findall(r"location\.href='(.+)'", r.text)[0]
            url = re.compile(
                r'((http://[-A-Za-z0-9+&@#%?=~_|!:,.;]+)/[-A-Za-z0-9+&@#/%?=~_|!:,.;]'
                r'+index\.jsp\?([-A-Za-z0-9+&@#/%=~_|]+))').findall(url)[0]
        except IndexError:
            logging.error('Invalid response of generate_204 request. Are you connected to HIT-WLAN?')
            raise GenericBadResponseException('generate_204 made an invalid response')

        # url[0]: full url
        # url[1]: host root url
        # url[2]: GET parameters

        if not url or len(url) != 3:
            if url:
                logging.error(f'Parse result: {url}')
            raise BadProbeResponseException(f'failed to parse page (status_code={r.status_code}): {r.text}')

        logging.debug(f'Initial page parsing result{len(url)}: {url}')
        full_url, url_root, query_string = url
        if not auth_server_host:
            auth_server_host = self._login_root_url or url_root
        self._login_root_url = auth_server_host

        # fetch login page
        ses = self._session
        print('Load pre-login page...')
        r = ses.get(full_url)

        # txt = gzip.decompress(r.content).decode('gbk') if '登录' not in r.text else r.text
        if '登录' not in RuiJie.magic_decompress_gzip(r.content).decode('gbk'):
            raise GenericBadResponseException(f'bad page `{r.url}`: not a valid login page')

        # send login request
        print('Send login payload...')
        logging.info('Send login payload.')
        r = ses.post(auth_server_host + '/eportal/InterFace.do?method=login', data={
            'userId': username,
            'password': password,
            'service': "",
            'queryString': query_string,
            'operatorPwd': "",
            'operatorUserId': "",
            'validcode': '',
            'passwordEncrypt': False
        })

        def __is_success(r: requests.Response):
            try:
                return r.json().get('result') == 'success'
            except ValueError:
                return False

        if __is_success(r):
            logging.debug(f'Login server response: {r.json()}')
            # update user_index from response
            if not (user_index := r.json().get('userIndex')):
                raise GenericBadResponseException('success response does not contain userIndex')
            self._user_index = user_index

            logging.info('Logged in successfully.')
            print('Logged in successfully. Checking Internet...')
            if has_internet():
                return True
            else:
                logging.error('We probably are not connected.')
                print('Failed to connect to the Internet.')
        else:
            # j = json.loads(r.text)
            # error_message = j.get("message")
            logging.error(
                f'Failed to login! Please check if you are using HIT-WLAN and your username&password pair is valid.')
            print(f'Failed to login! response: {r.text}')
        return False

    def set_senseless_login(self, enabled: bool = True, user_index: str = None, mac: str = None) -> bool:
        if not user_index and not self._user_index:
            raise ValueError('no valid user_index available')
        ses = self._session
        r = ses.post(self._login_root_url + '/eportal/InterFace.do?method={}'.format({
                                                                                         True: 'registerMac',
                                                                                         False: 'cancelMac'
                                                                                     }[enabled]), data={
            'mac': mac or '',
            'userIndex': user_index or self._user_index
        })
        try:
            logging.debug(f'Response: {r.text}')
            return r.json().get('result') == 'success'
        except ValueError:
            logging.error(f'Invalid response (JSON expected): {r.text}')
            return False

    def logout(self, user_index: str = None) -> bool:
        if not user_index and not self._user_index:
            raise ValueError('no valid user_index available')
        ses = self._session
        r = ses.post(self._login_root_url + '/eportal/InterFace.do?method=logout', data={
            'userIndex': user_index or self._user_index
        })
        logging.debug(f'logout response: `{r.text}`')
        return r.status_code == 200 and not r.text


def main():
    try:
        if has_internet():
            logging.info('Already connected. Quit.')
            print('Already connected. Quit.')
            return
    except IOError:
        logging.error('Cannot get response of generate_204.')
        print('Cannot check Internet connection. Please connect to HIT-WLAN firstly.')
        return

    try:
        # check config file
        if not os.path.isfile(CONFIG_FILE):
            logging.info(f'Config file {CONFIG_FILE} does not exist. Ask the user to set basic information.')
            print('It seems that it is the first time you use this program.')
            print(f'These configurations will be saved in file "{CONFIG_FILE}". Please do not delete it.')
            print(
                'Since the password is stored in plain text, I recommend you encrypting this file with Bitlocker or EFS.')

            username = input('Your Student ID:')
            password = input('Password:')

            cfg = {
                'username': username,
                'password': password
            }

            with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                json.dump(cfg, f)
        else:
            logging.debug('Reading config file.')
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                cfg = json.load(f)

            if 'username' not in cfg:
                print('username is not defined in the config file.')
                exit()
            if 'password' not in cfg:
                print('password is not defined in the config file.')
                exit()

            username = cfg['username']
            password = cfg['password']
    except IOError as e:
        logging.error(e)
        print(f'Failed to read configuration file: {e}')
        return

    helper = LoginHelper()

    try:
        if helper.login(username, password):
            logging.info('Successfully connected to the Internet. Quit.')
            print('Enjoy the Internet!')
            helper.set_senseless_login()
        else:
            logging.error('Failed to login.')
    except BadProbeResponseException as e:
        logging.error(e)
        logging.error('Maybe not using HIT-WLAN. Quit.')
        print(f'Failed to parse page: {e}')
        print('Please make sure that you have connected to HIT-WLAN.')
    # except Exception as e:
    #     logging.error(e)
    #     print(f'An unexpected exception occurred while logging in: {e.__class__.__name__}: {e}')
    #     print('Please check your network configuration in system settings and try again.')


if __name__ == "__main__":
    if '--debug' in sys.argv or '--verbose' in sys.argv or '-v' in sys.argv:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO
    logging.basicConfig(level=log_level, filename=LOG_FILE, filemode='a',
                        format='[%(levelname)s][%(asctime)s][line:%(lineno)d] %(message)s')
    main()
