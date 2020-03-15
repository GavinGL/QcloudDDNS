#!/usr/bin/env python3
# -*- coding: utf-8 -*-
 
from django.conf import settings
import base64
import hashlib
import hmac
import random
import time
import operator
import json
import urllib.parse
import re
import requests
from ntpdatetime import now
import urllib3

import logging
from loggerPrint import Logger

logger = Logger('./qcloud.log',clevel=logging.ERROR ,Flevel=logging.INFO)
urllib3.disable_warnings()
 
class QcloudApi():
    def __init__(self):
        self.SecretId = 'mySecretId'
        self.secretKey = 'mySecretKey'
 
    def get(self, module, action, **params):
        config = {
            'Action': action,
            'Nonce': random.randint(10000, 99999),
            'SecretId': self.SecretId,
            'SignatureMethod': 'HmacSHA256',
            'Timestamp': int(time.time()),
        }
        url_base = '{0}.api.qcloud.com/v2/index.php?'.format(module)
 
        params_all = dict(config, **params)
 
        params_sorted = sorted(params_all.items(), key=operator.itemgetter(0))

        srcStr = 'GET{0}'.format(url_base) + ''.join("%s=%s&" % (k , v) for k, \
            v in params_sorted)[:-1]

        signStr = base64.b64encode(hmac.new(bytes(self.secretKey, encoding='utf-8'), \
            bytes(srcStr, encoding='utf-8'), digestmod=hashlib.sha256).digest()).decode('utf-8')

        config['Signature'] = signStr

        params_last = dict(config, **params)

        params_url = urllib.parse.urlencode(params_last)
        
        url = 'https://{0}&'.format(url_base) + params_url

        http = urllib3.PoolManager()
        r = http.request('GET', url=url, retries=False)
        ret = json.loads(r.data.decode('utf-8'))
        if ret.get('code', {}) == 0:
            logger.debug('解析正常')
            return ret
        else:
            logger.error('解析失败')
            raise Exception(ret)      

    def update(self):
        ret = self.get(module='cns', action='DomainList')
        for count in range(len(ret['data']['domains'])):
            if  ret['data']['domains'][count].get('name') == myDomain:
                ret1 = self.get(module='cns', action='RecordList', domain=myDomain, length=100)
                for num in range(len(ret1['data']['records'])):
                    if ret1['data']['records'][num]['name'] == subDomain:
                        if ret1['data']['records'][num]['value'] == remoteIP:
                            logger.info("公网IP未变更 [%s]"%remoteIP)
                        else:
                            myrecordId = int(ret1['data']['records'][num]['id'])
                            ret = self.get(module='cns', action='RecordModify', domain=myDomain, \
                                recordId=myrecordId, subDomain=subDomain, value=remoteIP, recordType='A', \
                                recordLine='默认')
                            logger.info("云解析更新成功 [%s]"%remoteIP)
                        break
                break

def get_ip():
    ntp_now,fetched = now()
    response = requests.get("http://txt.go.sohu.com/ip/soip",headers=headers)
    ip=re.findall(r'\d+.\d+.\d+.\d+',response.text)
    logger.debug('公网IP获取正常')
    return ip

if __name__ == '__main__':
    headers = {'content-type': 'application/json','User-Agent': 
        'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:22.0) Gecko/20100101 Firefox/22.0'}
    myDomain = 'myDomainName'
    subDomain = 'mySubDomainName'
    while True:
        remoteIP = get_ip()[0]
        qcloud = QcloudApi()
        qcloud.update()
        time.sleep(600)
