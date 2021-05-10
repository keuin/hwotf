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
    import logging
except ModuleNotFoundError as e:
    print(f'Some essential modules are missing. Please run "pip install {e.name}" and try again.')
    exit()


def encrypt_password(plain_password):
    e=10001
    d=0
    n=int("9c2899b8ceddf9beafad2db8e431884a79fd9b9c881e459c0e1963984779d6612222cee814593cc458845bbba42b2d3474c10b9d31ed84f256c6e3a1c795e68e18585b84650076f122e763289a4bcb0de08762c3ceb591ec44d764a69817318fbce09d6ecb0364111f6f38e90dc44ca89745395a17483a778f1cc8dc990d87c3",16)
    p=0
    q=0
    u=0


CONFIG_FILE = 'hit.senseless.json'
LOG_FILE = 'hit.senseless.log'
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)'

logging.basicConfig(level=logging.INFO, filename=LOG_FILE, filemode='a', format='[%(levelname)s][%(asctime)s][line:%(lineno)d] %(message)s')    

if __name__ == "__main__":
    try:
        # check config file
        if not os.path.isfile(CONFIG_FILE):
            logging.info(f'Config file {CONFIG_FILE} does not exist. Ask the user to set basic information.')
            print('It seems that it is the first time you use this program.')
            print(f'These configurations will be saved in file "{CONFIG_FILE}". Please do not delete it.')
            print('Since the password is stored in plain text, I recommend you encrypting this file with Bitlocker or EFS.')
            
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
        exit()

    try:
        # detect the Internet connection
        r = requests.get('http://www.qq.com')

        if '腾讯' in r.text:
            logging.info('Already connected to the Internet. Quit.')
            print('You are already connected. Enjoy the Internet!')
            exit()
        
        # get the auth page address
        url = re.compile(r'((http://[-A-Za-z0-9+&@#%?=~_|!:,.;]+)/[-A-Za-z0-9+&@#/%?=~_|!:,.;]+index\.jsp\?([-A-Za-z0-9+&@#/%=~_|]+))').findall(r.text)

        # url[0]: full url
        # url[1]: host address
        # url[2]: GET parameters

        if not url or len(url[0]) != 3:
            logging.error(f'Failed to parse page (status_code={r.status_code}): {r.text}')
            if url:
                logging.error(f'Parse result: {url}')
            logging.error('Maybe not using HIT-WLAN. Quit.')
            print('Failed to parse page:', r.text)
            print('Please make sure that you have connected to HIT-WLAN.')
            exit()
        else:
            logging.debug(f'Initial page parsing result{len(url)}: {url}')
            url = url[0]

        ses = requests.session()
        ses.headers['User-Agent'] = USER_AGENT
        
        print('Loading pre-login page...')
        logging.info('Initializing login session.')
        r = ses.get(url[0])
        txt = gzip.decompress(r.content).decode('gbk') if '登录' not in r.text else r.text
        assert '登录' in txt, f'bad page: {txt}'
        
        print('Sending login payload...')
        logging.info('Sending login payload.')
        r = ses.post(url[1] + '/eportal/InterFace.do?method=login', data={
            'userId': username,
            'password': password,
            'service': "",
            'queryString': url[2],
            'operatorPwd': "",
            'operatorUserId': "",
            'validcode': '',
            'passwordEncrypt': False
        })
        
        if 'success' in r.text:
            logging.info('Logged in successfully.')
            print('Logged in successfully. Checking Internet...')
            r = requests.get('http://www.qq.com')
            if '腾讯' in r.text:
                logging.info('Successfully connected to the Internet. Quit.')
                print('Enjoy the Internet!')
                exit(0)
            else:
                logging.error(f'Internet check failed: www.qq.com make a response (status_code={r.status_code}): {r.text}')
                print('Failed to connect to the Internet.')
        else:
            # j = json.loads(r.text)
            # error_message = j.get("message")
            logging.error(f'Failed to login! Please check if you are using HIT-WLAN and your username&password pair is valid.')
            print(f'Failed to login! response: {r.text}')
    except IOError as e:
        logging.error(e)
        print(f'An unexpected exception occurred while logging in: {e}')
        print('Please check your network configuration in system settings and try again.')

