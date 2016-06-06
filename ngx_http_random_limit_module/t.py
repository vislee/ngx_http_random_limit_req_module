#!/usr/bin/env python
#
# -*- coding: UTF-8 -*-
#
# simple test python
#
#

"""
ngproxy conf
sae_limit_cache_zone_size 64K;
sae_limit_continue 300s;

location /ngproxy/rule {
    sae_limit_ip;
    allow 127.0.0.1;
    allow 10.210.77.245;
    deny all;
}

if ($sae_limit_act = "deny") {
    return 490;
}

error_page 490 =603 /random_limit_req.html;
location = /random_limit_req.html {
    root   html;
}

hostip = "127.0.0.1:8099"

localHost = "liwqcc.com"

"""

import urllib2
import urllib
import time
import inspect
import sys


hostip = "127.0.0.1:8099"
localHost = "liwq.cn"

baseurl = "http://%s/rule" %hostip
seturl = baseurl + "/set"
geturl = baseurl + "/get"
delurl = baseurl + "/del"
testurl = "http://%s/" %hostip
testurlignore = "http://%s/hello.js" %hostip


def myCurl(line, res, url, args=None, host=None, output=True):
    line += "->"+str(inspect.currentframe().f_lineno-1)
    ret = True
    resp = None
    stat_code = 200
    stat_msg = "error"


    full_url = url
    if args is not None:
        data = urllib.urlencode(args)
    
        if data is not None:
            full_url += '?' + data

    opener = urllib2.build_opener(urllib2.HTTPHandler())


    req = urllib2.Request(full_url)

    req.add_header('User-agent', 'Mozilla/5.0')
    if host is not None:
        req.add_header('Host', host)

    try:
        resp = opener.open(req)
    except urllib2.HTTPError as e:
        stat_code = e.code
        stat_msg = e.reason
    else:
        stat_code = resp.getcode()
        stat_msg = resp.read()

    if res.isdigit():
        if stat_code != int(res):
            ret = False
            if output:
                print "line:%s <%d> != <%d>" %(str(line), int(stat_code), int(res))
    else:
        if not stat_msg.startswith(res):
            ret = False
            if output:
                print "line:%s <%s> is not startswith <%s>" %(str(line), str(stat_msg), str(res))

    return ret

def test_get_rule_res(line, domain):
    line +="->"+str(inspect.currentframe().f_lineno-1)
    res = resp = urllib2.urlopen(geturl + "?domain=" + domain)
    return res.read()


def test_set_rule(line, domain="test.com", expire="3"):
    line +="->"+str(inspect.currentframe().f_lineno-1)
    args = {}
    args["domain"] = domain
    args["expire"] = expire
    return myCurl(line, "ok", seturl, args)

def del_rule(line, args):
    line +="->"+str(inspect.currentframe().f_lineno-1)
    return myCurl(line, "ok", delurl, args)

def test_get_rule(line, domain = "test.com"):
    line +="->"+str(inspect.currentframe().f_lineno-1)
    args = {}
    args["domain"] = domain
    res = myCurl(line, "ok", seturl, args)
    if res:
        return myCurl(line, "domain="+domain, geturl, args)
    return False


def test_expire_rule(line):
    line +="->"+str(inspect.currentframe().f_lineno-1)
    args = {}
    domain = "liwq.cn"
    args["domain"] = domain
    if test_get_rule(line, domain):
        if test_set_rule(line, domain, "0"):
            args["expire"] = "1"
            return myCurl(line, "null", geturl, args);
    return False

def test_del_rule(line):
    line +="->"+str(inspect.currentframe().f_lineno-1)
    args = {}
    domain = "liwq.cc"
    args["domain"] = domain
    args["expire"] = "300"
    if test_get_rule(line, domain):
        if del_rule(line, args):
            return myCurl(line, "null", geturl, args);
    return False


def test_block_res(line, res = "603", host=None):
    line +="->"+str(inspect.currentframe().f_lineno-1)
    if test_set_rule(line, "liwq.cc", "300"):
        kk = 0
        for j in range(1,401):
            if myCurl(line, res, testurl, None, localHost, False):
                kk += 1
        print "block count: %d/%d" %(kk, j)
        if float(kk)/j > 0.4 and float(kk)/j < 0.6:
            return True
    return False

def test_ignore_res(line, res = "404", host=None):
    line +="->"+str(inspect.currentframe().f_lineno-1)
    if test_set_rule(line, "liwq.cc", "300"):
        kk = 0
        for j in range(1,401):
            if myCurl(line, res, testurlignore, None, localHost, False):
                kk += 1
        print "ignore count: %d/%d" %(kk, j)
        if kk == j:
            return True
    return False


def test_lru_block(line):
    line +="->"+str(inspect.currentframe().f_lineno-1)

    args = {}
    args["domain"] = "zz.cn"
    args["expire"] = 700
    if myCurl(line, "ok", seturl, args):
        if not myCurl(line, "domain=zz.cn", geturl, args):
            return False

    k = 0;
    for i in range(1, 21):
        for j in range(1, 81):
            domain = "mmnnoo%02d%02d" %(i, j)
            if test_set_rule(line, domain, "500"):
                k += 1;
    print "set times %d" %k

    if not myCurl(line, "domain=zz.cn", geturl, args, output=False):
        if myCurl(line, "ok", seturl, args, output=False):
            if not myCurl(line, "domain=zz.cn", geturl, args, output=False):
                return False

    return True


def main():
    line = str(inspect.currentframe().f_lineno-1)
    print "test set rule:"
    if test_set_rule(line):
        print "[ok]"
    else:
        print "===>[err]"

    print "test get rule:"
    if test_get_rule(line):
        print "[ok]"
    else:
        print "===>[err]"

    print "test expire rule:"
    if test_expire_rule(line):
        print "[ok]"
    else:
        print "===>[err]"

    print "test del rule"
    if test_del_rule(line):
        print "[ok]"
    else:
        print "===>[err]"

    print "test block ip:"
    if test_block_res(line):
        print "[ok]"
    else:
        print "===>[err]"

    print "ignore block ip:"
    if test_ignore_res(line):
        print "[ok]"
    else:
        print "===>[err]"

    print "test lru block:"
    if test_lru_block(line):
        print "[ok]"
    else:
        print "===>[err]"

    print "done"


if __name__ == '__main__':
    main()

