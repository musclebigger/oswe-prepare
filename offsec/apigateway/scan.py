#!/usr/bin/env python3
#由于扫描工具慢，要快速枚举端口可用需要手搓ssrf的工具, 利用ssrf枚举内网
import argparse
import requests
import ipaddress
from requests.exceptions import RequestException, Timeout

# 探测是否主机的存活内网地址
def test_alive_host(ip, url,timeout,verbose):
 #   possible_ip_range = [
 #      ipaddress.ip_network('10.0.0.0/8'),
#       ipaddress.ip_network('172.16.0.0/12')
#        ipaddress.ip_network('192.168.0.0/16')
 #   ]
    alive_hosts = []
    possible_ip_range = ipaddress.ip_network(ip)

    for ip in possible_ip_range.hosts():
        try:
            r = requests.post(url, json={"url":"http://{host}".format(host=ip)}, timeout=timeout) # 超过timeout就不存活的host地址
            if verbose:
                print(ip, r.status_code, repr(r.text[:200]))
            # 判断存活的条件
            alive_hosts.append(ip)
            print(f"确认主机{ip}存活")
        except Timeout:
            continue
        except RequestException:
            # 连接被拒绝、DNS 解析失败等其它错误，按需求返回 False
            print(f"访问主机{ip}DNS报错")
            continue

    return alive_hosts

# 探测端口存活
def test_alive_ports(url,target, ports, verbose):
    for p in ports:
        try:
            r = requests.post(url, json={"url":"http://{host}:{port}".format(host=target,port=int(p))}, timeout=timeout)

            if verbose:
                print("{port:0} \t {msg}".format(port=int(p), msg=r.text))

            if "You don't have permission to access this." in r.text: #有回复
                print("{port:0} \t OPEN - returned permission error, therefore valid resource".format(port=int(p)))
            elif "ECONNREFUSED" in r.text:
                print("{port:0} \t CLOSED".format(port=int(p)))
            elif "--------FIX ME--------" in r.text: #有回复
                print("{port:0} \t OPEN - returned 404".format(port=int(p)))
            elif "--------FIX ME--------" in r.text:
                print("{port:0} \t ???? - returned parse error, potentially open non-http".format(port=int(p)))
            elif "--------FIX ME--------" in r.text: #有回复
                print("{port:0} \t OPEN - socket hang up, likely non-http".format(port=int(p)))
            else:
                print("{port:0} \t {msg}".format(port=int(p), msg=r.text))
        except requests.exceptions.Timeout:
            print("{port:0} \t timed out".format(port=int(p)))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-t','--target', help='host/ip to target', required=True)
    parser.add_argument('--timeout', help='timeout', required=False, default=3) #确认存活参数
    parser.add_argument('-v','--verbose', help='enable verbose mode', action="store_true", default=False)
    parser.add_argument('-i','--ip', help='scanning internal ips', required=True) #输入地址端'192.168.0.0/16'

    args = parser.parse_args()
    # 常用端口
    ports = ['22','80','443', '1433', '1521', '3306', '3389', '5000', '5432', '5900', '6379','8000','8001','8055','8080','8443','9000']
    timeout = float(args.timeout)
    verbose = args.verbose
    target  = args.target
    ips = args.ip
    print("设定不存活判定时间为{timeout}".format(timeout=timeout))

    print("开始探测存活主机")
    alive_host = test_alive_host(ips, target, timeout, verbose)
    print(f"探测主机存活完毕，存活主机包括{alive_host}")

    print("开始探测存活主机的端口号存活情况")
    for ip in alive_host:
        test_alive_ports(target, ip, ports, verbose)