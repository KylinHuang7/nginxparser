#!/usr/bin/python
# -*- coding: utf-8 -*-

# =============================================================================
#  @desc       
#  @version    2.0.0
#  @author     KylinHuang
#  @date       2017-11-21
# =============================================================================

import sys
import json
import nginxparser


class NginxAnalysis(object):
    def __init__(self):
        self.config = nginxparser.NginxConfig()

    def load(self, path, ignore_list=None):
        if ignore_list is None:
            ignore_list = []
        config = nginxparser.NginxConfig.load(path, ignore_list)
        if config:
            self.config.merge(config)

    def getHostsByHost(self, host):
        return self.config.getHostsByHost(host)

    def getHostsByHostPort(self, host, port=80):
        return self.config.getHostsByHostPort(host, port)

    def getUpstreamsByUrl(self, url, ignore_list=None):
        if ignore_list is None:
            ignore_list = []
        upstream_list = self.config.getUpstreamsByUrl(url)
        return [x for x in upstream_list if x not in ignore_list]

    def getHostsByUrl(self, url):
        return self.config.getHostsByUrl(url)


def usage():
    print "Usage:                                "
    print sys.argv[0] + " get_upstream <url>"
    print sys.argv[0] + " get_ip <url>"
    print sys.argv[0] + " get_related_ip <ip[:port]>"


if __name__ == '__main__':
    if len(sys.argv) != 3:
        usage()
        sys.exit(1)
    nginx_obj = NginxAnalysis()
    nginx_obj.load('/usr/local/nginx/config/')
    if sys.argv[1] == 'get_upstream':
        print json.dumps(nginx_obj.getUpstreamsByUrl(sys.argv[2]))
    elif sys.argv[1] == 'get_ip':
        print json.dumps(nginx_obj.getHostsByUrl(sys.argv[2]))
    elif sys.argv[1] == 'get_related_ip':
        if ':' in sys.argv[2]:
            host, port = sys.argv[2].split(':')
        else:
            host, port = sys.argv[2], 80
        print json.dumps(nginx_obj.getHostsByHostPort(host, port))
    else:
        usage()
