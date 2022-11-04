#!/usr/bin/python
# -*- coding: utf-8 -*-

# =============================================================================
#  @desc       
#  @version    2.0.0
#  @author     KylinHuang
#  @date       2017-11-21
# =============================================================================

import os
import re
import itertools
import codecs
import urlparse


class NginxComponent(object):
    def parse_statement(self, config_lines):
        components = []
        line_index = 0
        while line_index < len(config_lines):
            config_line = config_lines[line_index].strip()
            line_index += 1
            config_list = re.split('\s+', config_line.strip(" \t\r\n;"))
            components.extend(config_list)
            if config_line.endswith(';'):
                break
        return components, line_index

    def parse_block(self, config_lines):
        block_components = []
        block_lines = []
        line_index = 0
        block_brackets = 0
        block_state = 0
        while line_index < len(config_lines):
            config_line = config_lines[line_index].strip()
            line_index += 1
            if '{' in config_line and block_state == 0:
                block_state = 1
                config_list = re.split('\s+', config_line[:config_line.find('{')].strip())
                block_components.extend(config_list)
                block_lines.append(config_line[config_line.find('{') + 1:].strip())
            elif block_state == 0:
                config_list = re.split('\s+', config_line.strip())
                block_components.extend(config_list)
            else:
                block_lines.append(config_line)

            block_brackets += config_line.count('{')
            block_brackets -= config_line.count('}')
            if block_state == 1 and block_brackets == 0:
                break
        return block_components, block_lines, line_index


class NginxUpstream(NginxComponent):
    def __init__(self, name):
        self.name = name
        self.servers = []

    def add_server(self, server):
        if not server.down:
            self.servers.append(server)

    @classmethod
    def parse(cls, config_lines):
        upstream = NginxUpstream(None)
        block_components, block_lines, line_index = upstream.parse_block(config_lines)
        if not block_components or block_components[0] != 'upstream':
            return None, 1

        upstream.name = block_components[1]

        i = 0
        while i < len(block_lines):
            config_line = block_lines[i]
            i += 1
            if config_line.startswith('server'):
                server, j = NginxUpstreamServer.parse(block_lines[i - 1:])
                i += (j - 1)
                if server:
                    upstream.add_server(server)
        return upstream, line_index

    def searchByHostAndPort(self, host, port=80):
        for server in self.servers:
            if server.equals(host, port):
                return True
        return False

    def searchByHost(self, host):
        for server in self.servers:
            if server.effects(host):
                return True
        return False

    def getServerHostPorts(self):
        return tuple(set([server.host + ':' + server.port for server in self.servers]))

    def getServerHosts(self):
        return tuple(set([server.host for server in self.servers]))

    def __str__(self):
        return "NginxUpstream(name: {0}, servers: {1})".format(self.name, ", ".join([str(d) for d in self.servers]))


class NginxUpstreamServer(NginxComponent):
    def __init__(self, host, port=80, weight=1, max_conns=0, max_fails=1, fail_timeout=10, backup=False, down=False):
        self.host = host
        self.port = port
        self.weight = weight
        self.max_conns = max_conns
        self.max_fails = max_fails
        self.fail_timeout = fail_timeout
        self.backup = backup
        self.down = down

    @classmethod
    def parse(cls, config_lines):
        server = NginxUpstreamServer(None)
        components, line_index = server.parse_statement(config_lines)
        if not components or components[0] != 'server':
            return None, 1

        if ':' in components[1]:
            server.host, server.port = components[1].split(':')
        else:
            server.host = components[1]
        for component in components[2:]:
            if component == 'down':
                server.down = True
            elif component == 'backup':
                server.backup = True
            elif '=' in component:
                key, value = component.split('=')
                if key == 'weight':
                    server.weight = value
                elif key == 'max_conns':
                    server.max_conns = value
                elif key == 'max_fails':
                    server.max_fails = value
                elif key == 'fail_timeout':
                    server.fail_timeout = value
        return server, line_index

    def equals(self, host, port=80):
        if self.host == host and self.port == port:
            return True
        return False

    def effects(self, host):
        if self.host == host:
            return True
        return False

    def __str__(self):
        return "NginxUpstreamServer(host: {0}, port: {1}, weight: {2}, " \
               "max_conns: {3}, max_fails: {4}, fail_timeout: {5}, backup: {6}, down: {7})".format(
            self.host, self.port, self.weight, self.max_conns, self.max_fails, self.fail_timeout, self.backup,
            self.down)


class NginxServer(NginxComponent):
    def __init__(self):
        self.server_name = None
        self.location_list = []

    def set_server_name(self, server_name):
        self.server_name = server_name

    def add_location(self, location):
        self.location_list.append(location)

    @classmethod
    def parse(cls, config_lines):
        server = NginxServer()
        block_components, block_lines, line_index = server.parse_block(config_lines)
        if not block_components or block_components[0] != 'server':
            return None, 1

        i = 0
        while i < len(block_lines):
            config_line = block_lines[i]
            i += 1
            if config_line.startswith('server_name'):
                server_name, j = NginxServerName.parse(block_lines[i - 1:])
                i += (j - 1)
                if server_name:
                    server.set_server_name(server_name)
            elif config_line.startswith("location"):
                location, j = NginxServerLocation.parse(block_lines[i - 1:])
                i += (j - 1)
                if location:
                    server.add_location(location)
            elif config_line.startswith("rewrite"):
                rewrite_rule, j = NginxServerLocationRewrite.parse(block_lines[i - 1:])
                i += (j - 1)
                if rewrite_rule:
                    server.add_location(rewrite_rule)
        return server, line_index

    def match(self, url, server_list):
        parse_result = urlparse.urlparse(url)
        if ':' in parse_result.netloc:
            hostname = parse_result.netloc[:parse_result.netloc.find(':')]
        else:
            hostname = parse_result.netloc
        parse_location = re.sub('\/+', '/', parse_result.path)
        matched_name, match_groups = self.server_name.match(hostname)
        match_result = dict(('arg_' + d[0], d[1]) for d in urlparse.parse_qsl(parse_result.query))
        match_result['args'] = parse_result.query
        match_result['query_string'] = parse_result.query
        if match_groups:
            match_result.extend(match_groups.groupdict())
        if not matched_name:
            return False, 0

        # A location can either be defined by a prefix string, or by a regular expression. Regular 
        # expressions are specified with the preceding "~*" modifier (for case-insensitive matching), 
        # or the "~" modifier (for case-sensitive matching). To find location matching a given request, 
        # nginx first checks locations defined using the prefix strings (prefix locations). Among them, 
        # the location with the longest matching prefix is selected and remembered. Then regular 
        # expressions are checked, in the order of their appearance in the configuration file. The search 
        # of regular expressions terminates on the first match, and the corresponding configuration is 
        # used. If no match with a regular expression is found then the configuration of the prefix 
        # location remembered earlier is used.
        prefix_matched, prefix_type, prefix_location, prefix_upstream, prefix_code = "", None, None, None, 200
        regex_location, regex_upstream, regex_code = None, None, 200
        matched_location, matched_upstream, matched_code = None, None, 200
        for location in self.location_list:
            if type(location) == NginxServerLocationRewrite:
                match_rewrite = location.match(parse_location, server_list, match_result=match_result)
                if match_rewrite:
                    return match_rewrite, 302
                continue
            location_result, match_type, match_upstream, match_code = location.match(parse_location, server_list,
                                                                                     match_result=match_result)
            if not location_result:
                continue
            elif match_type == '=':
                matched_location, matched_upstream, matched_code = location, match_upstream, match_code
                break
            elif match_type == '^~' or match_type == '':
                if len(location_result) > len(prefix_matched):
                    prefix_matched, prefix_type, prefix_location, prefix_upstream, prefix_code \
                        = location_result, match_type, location, match_upstream, match_code
            elif match_type == '~*' or match_type == '~':
                if not regex_location:
                    regex_location, regex_upstream, regex_code = location, match_upstream, match_code
        if not matched_location:
            if prefix_type == '^~':
                matched_location, matched_upstream, matched_code = prefix_location, prefix_upstream, prefix_code
            elif regex_location:
                matched_location, matched_upstream, matched_code = regex_location, regex_upstream, regex_code
            else:
                matched_location, matched_upstream, matched_code = prefix_location, prefix_upstream, prefix_code
        return matched_upstream, matched_code

    def __str__(self):
        return "NginxServer(server_name: {0}, location_list: {1})".format(self.server_name, ", ".join(
            [str(d) for d in self.location_list]))


class NginxServerName(NginxComponent):
    def __init__(self):
        self.exact_hosts = []
        self.starting_asterisk_hosts = []
        self.ending_asterisk_hosts = []
        self.regular_hosts = []
        self.default_hosts = []

    def add_hosts(self, host):
        if host.startswith('^'):
            self.regular_hosts.append(host)
        elif host.startswith('*'):
            self.starting_asterisk_hosts.append(host)
            self.starting_asterisk_hosts.sort(key=lambda (x): len(x), reverse=True)
        elif host.startswith('.'):
            self.starting_asterisk_hosts.append(host)
            self.starting_asterisk_hosts.sort(key=lambda (x): len(x), reverse=True)
        elif host.endswith('*'):
            self.ending_asterisk_hosts.append(host)
            self.ending_asterisk_hosts.sort(key=lambda (x): len(x), reverse=True)
        elif host == '_':
            self.default_hosts.append(host)
        else:
            self.exact_hosts.append(host)

    def match(self, host_name):
        # During searching for a virtual server by name, if the name matches more than one of the 
        # specified variants, (e.g. both a wildcard name and regular expression match), the first 
        # matching variant will be chosen, in the following order of priority:
        #  1 the exact name
        #  2 the longest wildcard name starting with an asterisk, e.g. "*.example.com"
        #  3 the longest wildcard name ending with an asterisk, e.g. "mail.*"
        #  4 the first matching regular expression (in order of appearance in the configuration file)
        for host in self.exact_hosts:
            if host_name == host:
                return True, None
        for host in self.starting_asterisk_hosts:
            if host.startswith('.'):
                pure_host = host.strip('.')
                if host_name.endswith(pure_host):
                    return True, None
            elif host.startswith('*'):
                pure_host = host.lstrip('*')
                if host_name.endswith(pure_host):
                    return True, None
        for host in self.ending_asterisk_hosts:
            pure_host = host.rstrip('*')
            if host_name.startswith(pure_host):
                return True, None
        for host in self.regular_hosts:
            pure_host = host.lstrip('~')
            if '(?<' in pure_host:  # ?<name> Perl 5.10 compatible syntax, supported since PCRE-7.0
                pure_host.replace('(?<', '(?P<')
            if "(?'" in pure_host:  # ?'name' Perl 5.10 compatible syntax, supported since PCRE-7.0
                pure_host = re.sub(r'\(\?\'([^\']+)\'', r'(?P<\1>', pure_host)
            pure_regex = re.compile(pure_host)
            m = pure_regex.search(host_name)
            if m:
                return True, m
        for host in self.default_hosts:
            if host == '_':
                return True, None
        return False, None

    @classmethod
    def parse(cls, config_lines):
        server_name = NginxServerName()
        components, line_index = server_name.parse_statement(config_lines)
        if not components or components[0] != 'server_name':
            return None, 1

        for component in components[1:]:
            server_name.add_hosts(component)
        return server_name, line_index

    def __str__(self):
        return "NginxServerName(server_name: {0}; {1}; {2}; {3}; {4})".format(", ".join(self.exact_hosts),
                                                                              ", ".join(self.starting_asterisk_hosts),
                                                                              ", ".join(self.ending_asterisk_hosts),
                                                                              ", ".join(self.regular_hosts),
                                                                              ", ".join(self.default_hosts))


class NginxServerLocation(NginxComponent):
    def __init__(self, location):
        self.location = location.strip()
        self.upstreams = []
        self.sub_location = []

    def add_upstream(self, upstream):
        self.upstreams.append(upstream)

    def add_sub_location(self, location):
        self.sub_location.append(location)

    def match(self, location, server_list, match_result=None):
        if match_result is None:
            match_result = {}
        if self.location.startswith('^~'):
            location_result = self.location[2:].strip()
            match_type = '^~'
            match_regex = re.compile(location_result)
            m = match_regex.search(location)
            if not m:
                return False, "", None, 0
            match_result.update(m.groupdict())
        elif self.location.startswith('~*'):
            location_result = self.location[2:].strip()
            match_type = '~*'
            match_regex = re.compile(location_result, re.I)
            m = match_regex.search(location)
            if not m:
                return False, "", None, 0
            match_result.update(m.groupdict())
        elif self.location.startswith('~'):
            location_result = self.location[1:].strip()
            match_type = '~'
            match_regex = re.compile(location_result)
            m = match_regex.search(location)
            if not m:
                return False, "", None, 0
            match_result.update(m.groupdict())
        elif self.location.startswith('='):
            location_result = self.location[1:].strip()
            match_type = '='
            if location_result != location:
                return False, "", None, 0
        elif self.location.startswith('@'):
            return False, "", None, 0
        else:
            location_result = self.location
            match_type = ''
            if not location.startswith(location_result):
                return False, "", None, 0

        match_upstream = None
        match_code = 200
        if self.upstreams:
            for upstream in self.upstreams:
                if type(upstream) == NginxServerLocationProxyPass:
                    match_upstream = upstream.get_finally_upstream(match_result=match_result)
                    break
                elif type(upstream) == NginxServerLocationIf:
                    matched_condition = upstream.match(location, server_list, match_result=match_result)
                    if matched_condition:
                        match_upstream = matched_condition
                        break
                elif type(upstream) == NginxServerLocationSet:
                    match_result[upstream.name.lstrip('$')] = upstream.get_finally_value(match_result=match_result)
                elif type(upstream) == NginxServerLocationReturn:
                    match_upstream = upstream.code
                    break
                elif type(upstream) == NginxServerLocationRewrite:
                    matched_rewrite = upstream.match(location, server_list, match_result=match_result)
                    if matched_rewrite:
                        match_upstream = matched_rewrite
                        match_code = 302
        if type(match_upstream) is int:
            match_code = match_upstream
            match_upstream = None
        return location_result, match_type, match_upstream, match_code

    @classmethod
    def parse(cls, config_lines):
        location = NginxServerLocation("")
        block_components, block_lines, line_index = location.parse_block(config_lines)
        if not block_components or block_components[0] != 'location':
            return None, 1

        location.location = ' '.join(block_components[1:]).strip()

        i = 0
        while i < len(block_lines):
            config_line = block_lines[i]
            i += 1
            if config_line.startswith('if'):
                condition, j = NginxServerLocationIf.parse(block_lines[i - 1:])
                i += (j - 1)
                if condition:
                    location.add_upstream(condition)
            elif config_line.startswith("proxy_pass"):
                proxy_pass, j = NginxServerLocationProxyPass.parse(block_lines[i - 1:])
                i += (j - 1)
                if proxy_pass:
                    location.add_upstream(proxy_pass)
            elif config_line.startswith("set"):
                variable, j = NginxServerLocationSet.parse(block_lines[i - 1:])
                i += (j - 1)
                if variable:
                    location.add_upstream(variable)
            elif config_line.startswith("location"):
                sub_location, j = NginxServerLocation.parse(block_lines[i - 1:])
                i += (j - 1)
                if sub_location:
                    location.add_sub_location(sub_location)
            elif config_line.startswith("return"):
                return_code, j = NginxServerLocationReturn.parse(block_lines[i - 1:])
                i += (j - 1)
                if return_code:
                    location.add_upstream(return_code)
            elif config_line.startswith("rewrite"):
                rewrite_rule, j = NginxServerLocationRewrite.parse(block_lines[i - 1:])
                i += (j - 1)
                if rewrite_rule:
                    location.add_upstream(rewrite_rule)
        return location, line_index

    def __str__(self):
        return "NginxServerLocation(location: {0}, upstreams: {1})".format(self.location,
                                                                           ", ".join([str(d) for d in self.upstreams]))


class NginxServerLocationIf(NginxComponent):
    def __init__(self, condition):
        self.condition = condition.strip('() ')
        self.upstreams = []

    def set_condition(self, condition):
        self.condition = condition.strip('() ')

    def match(self, location, server_list, match_result=None):
        if match_result is None:
            match_result = {}
        explained_condition = re.sub('\$\{?\w+\}?', lambda x: str(
            '' if x.group(0).strip('${}') not in match_result else match_result[x.group(0).strip('${}')]),
                                     self.condition)
        splitted_condition = explained_condition.split(' ')
        if splitted_condition[1] == '~*':
            match_regex = re.compile(splitted_condition[2].strip('"\''), re.I)
            if not match_regex.search(splitted_condition[0]):
                return None
        elif splitted_condition[1] == '~':
            match_regex = re.compile(splitted_condition[2].strip('"\''))
            if not match_regex.search(splitted_condition[0]):
                return None
        elif splitted_condition[1] == '!~*':
            match_regex = re.compile(splitted_condition[2].strip('"\''), re.I)
            if match_regex.search(splitted_condition[0]):
                return None
        elif splitted_condition[1] == '!~':
            match_regex = re.compile(splitted_condition[2].strip('"\''))
            if match_regex.search(splitted_condition[0]):
                return None
        elif splitted_condition[1] == '!=':
            if splitted_condition[0] == splitted_condition[2].strip('"\''):
                return None
        elif splitted_condition[1] == '=':
            if splitted_condition[0] != splitted_condition[2].strip('"\''):
                return None
        if self.upstreams:
            for upstream in self.upstreams:
                if type(upstream) == NginxServerLocationProxyPass:
                    return upstream.get_finally_upstream(match_result=match_result)
                elif type(upstream) == NginxServerLocationSet:
                    match_result[upstream.name.lstrip('$')] = upstream.get_finally_value(match_result=match_result)
                elif type(upstream) == NginxServerLocationReturn:
                    return upstream.code
                elif type(upstream) == NginxServerLocationRewrite:
                    matched_rewrite = upstream.match(location, server_list, match_result=match_result)
                    if matched_rewrite:
                        return matched_rewrite

    @classmethod
    def parse(cls, config_lines):
        condition = NginxServerLocationIf("")
        block_components, block_lines, line_index = condition.parse_block(config_lines)
        if not block_components or block_components[0] != 'if':
            return None, 1

        condition.set_condition(' '.join(block_components[1:]))

        i = 0
        while i < len(block_lines):
            config_line = block_lines[i]
            i += 1
            if config_line.startswith("proxy_pass"):
                proxy_pass, j = NginxServerLocationProxyPass.parse(block_lines[i - 1:])
                i += (j - 1)
                if proxy_pass:
                    condition.upstreams.append(proxy_pass)
            elif config_line.startswith("set"):
                variable, j = NginxServerLocationSet.parse(block_lines[i - 1:])
                i += (j - 1)
                if variable:
                    condition.upstreams.append(variable)
            elif config_line.startswith("return"):
                return_code, j = NginxServerLocationReturn.parse(block_lines[i - 1:])
                i += (j - 1)
                if return_code:
                    condition.upstreams.append(return_code)
            elif config_line.startswith("rewrite"):
                rewrite_rule, j = NginxServerLocationRewrite.parse(block_lines[i - 1:])
                i += (j - 1)
                if rewrite_rule:
                    condition.upstreams.append(rewrite_rule)
        return condition, line_index

    def __str__(self):
        return "NginxServerLocationIf(condition: {0}, upstreams: {1})".format(self.condition, ", ".join(
            [str(d) for d in self.upstreams]))


class NginxServerLocationProxyPass(NginxComponent):
    def __init__(self, upstream):
        parse_result = urlparse.urlparse(upstream)
        self.upstream = parse_result.netloc

    def set_upstream(self, upstream):
        parse_result = urlparse.urlparse(upstream)
        self.upstream = parse_result.netloc

    def get_finally_upstream(self, match_result=None):
        if match_result is None:
            match_result = {}
        if '$' not in self.upstream:
            return self.upstream
        return re.sub('\$\{?\w+\}?', lambda x: str(
            '' if x.group(0).strip('${}') not in match_result else match_result[x.group(0).strip('${}')]),
                      self.upstream)

    @classmethod
    def parse(cls, config_lines):
        proxy_pass = NginxServerLocationProxyPass("")
        components, line_index = proxy_pass.parse_statement(config_lines)
        if not components or components[0] != 'proxy_pass':
            return None, 1
        proxy_pass.set_upstream(components[1])
        return proxy_pass, line_index

    def __str__(self):
        return "NginxServerLocationProxyPass(upstream: {0})".format(self.upstream)


class NginxServerLocationSet(NginxComponent):
    def __init__(self, name, value):
        self.name = name
        self.value = value

    def get_finally_value(self, match_result=None):
        if match_result is None:
            match_result = {}
        if '$' not in self.value:
            return self.value.strip('"\'')
        return re.sub('\$\{?\w+\}?', lambda x: str(
            '' if x.group(0).strip('${}') not in match_result else match_result[x.group(0).strip('${}')]),
                      self.value).strip('"\'')

    @classmethod
    def parse(cls, config_lines):
        variable = NginxServerLocationSet(None, None)
        components, line_index = variable.parse_statement(config_lines)
        if not components or components[0] != 'set':
            return None, 1
        variable.name = components[1]
        variable.value = components[2]
        return variable, line_index

    def __str__(self):
        return "NginxServerLocationSet(name: {0}, value: {1})".format(self.name, self.value)


class NginxServerLocationReturn(NginxComponent):
    def __init__(self, code):
        self.code = int(code)
        self.url = ''

    def set_code(self, code):
        self.code = int(code)

    @classmethod
    def parse(cls, config_lines):
        return_code = NginxServerLocationReturn(200)
        components, line_index = return_code.parse_statement(config_lines)
        if not components or components[0] != 'return':
            return None, 1
        if re.search('^\d+$', components[1]):
            return_code.set_code(components[1])
            if len(components) > 2:
                return_code.url = components[2]
        else:
            return_code.set_code(302)
            return_code.url = components[1]
        return return_code, line_index

    def __str__(self):
        return "NginxServerLocationReturn(code: {0})".format(self.code)


class NginxServerLocationRewrite(NginxComponent):
    def __init__(self):
        self.regex = ''
        self.rewrite_url = ''
        self.flag = ''

    def match(self, location, server_list, match_result=None):
        if match_result is None:
            match_result = {}
        match_regex = re.compile(self.regex, re.I)
        m = match_regex.search(location)
        if m:
            match_result.update(m.groupdict())
        else:
            return None

        if '$' not in self.rewrite_url:
            final_url = self.rewrite_url
        else:
            final_url = re.sub('\$\{?\w+\}?', lambda x: str(
                '' if x.group(0).strip('${}') not in match_result else match_result[x.group(0).strip('${}')]),
                               self.rewrite_url)
        result_list = []
        for server in server_list:
            matched_upstream, matched_code = server.match(final_url, server_list)
            if type(matched_upstream) is list:
                result_list.extend(matched_upstream)
            elif matched_upstream:
                result_list.append(matched_upstream)
        return list(set(result_list))

    @classmethod
    def parse(cls, config_lines):
        rewrite_rule = NginxServerLocationRewrite()
        components, line_index = rewrite_rule.parse_statement(config_lines)
        if not components or components[0] != 'rewrite':
            return None, 1
        rewrite_rule.regex = components[1]
        rewrite_rule.rewrite_url = components[2]
        if len(components) > 3:
            rewrite_rule.flag = components[3]
        return rewrite_rule, line_index

    def __str__(self):
        return "NginxServerLocationRewrite(regex: {0}, rewrite_url: {1})".format(self.regex, self.rewrite_url)


class NginxConfig(object):
    def __init__(self):
        self.server_list = []
        self.upstream_list = []

    def merge(self, config):
        if config:
            self.server_list.extend(config.server_list)
            self.upstream_list.extend(config.upstream_list)

    def getUpstreamByHostPort(self, host, port=80):
        return filter(lambda x: x.searchByHostAndPort(host, port), self.upstream_list)

    def getUpstreamByHost(self, host):
        return filter(lambda x: x.searchByHost(host), self.upstream_list)

    def getHostsByHostPort(self, host, port=80):
        host_list = [x.getServerHosts() for x in self.getUpstreamByHostPort(host, port)]
        return list(set(itertools.chain.from_iterable(host_list)))

    def getHostsByHost(self, host):
        host_list = [x.getServerHosts() for x in self.getUpstreamByHost(host)]
        return list(set(itertools.chain.from_iterable(host_list)))

    def getUpstreamsByUrl(self, url):
        result_list = []
        for server in self.server_list:
            matched_upstream, matched_code = server.match(url, self.server_list)
            if type(matched_upstream) is list:
                result_list.extend(matched_upstream)
            elif matched_upstream:
                result_list.append(matched_upstream)
        return list(set(result_list))

    def getHostsByUrl(self, url):
        stream_list = self.getUpstreamsByUrl(url)
        hosts = []
        for stream in self.upstream_list:
            if stream.name in stream_list:
                hosts.append(stream.getServerHosts())
        return list(set(itertools.chain.from_iterable(hosts)))

    def getHostsByUpstream(self, upstream):
        hosts = []
        for stream in self.upstream_list:
            if stream.name == upstream:
                hosts.append(stream.getServerHosts())
        return list(set(itertools.chain.from_iterable(hosts)))

    def getHostPortsByUpstream(self, upstream):
        hosts = []
        for stream in self.upstream_list:
            if stream.name == upstream:
                hosts.append(stream.getServerHostPorts())
        return list(set(itertools.chain.from_iterable(hosts)))

    @classmethod
    def parse(cls, filename):
        nginx_config = NginxConfig()
        config_lines = codecs.open(filename, 'r', 'gbk', 'replace').read().split('\n')
        i = 0
        while i < len(config_lines):
            config_line = config_lines[i].strip()
            if '#' in config_line:
                config_line = config_line[:config_line.find('#')].strip()
            i += 1
            if config_line == '':
                continue
            elif config_line.startswith('upstream'):
                upstream, j = NginxUpstream.parse(config_lines[i - 1:])
                i += (j - 1)
                if upstream:
                    nginx_config.upstream_list.append(upstream)
            elif config_line.startswith('server'):
                server, j = NginxServer.parse(config_lines[i - 1:])
                i += (j - 1)
                if server:
                    nginx_config.server_list.append(server)
        return nginx_config

    @classmethod
    def load(cls, filepath, ignore_list=None):
        if ignore_list is None:
            ignore_list = []
        if os.path.isfile(filepath):
            if filepath in ignore_list:
                return None
            filename, fileext = os.path.splitext(filepath)
            if fileext == '.conf':
                return cls.parse(filepath)
            else:
                return None
        elif os.path.isdir(filepath):
            filepath = filepath.rstrip('/')
            nginx_config = NginxConfig()
            for f in os.listdir(filepath):
                config = cls.load(filepath + '/' + f)
                if config:
                    nginx_config.merge(config)
            return nginx_config
        return None
