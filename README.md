# nginxparser

`nginxparser` is a python lib for parsing [nginx](http://nginx.org) configuration files.

## Usage

```python
import nginxparser

nginx_config_path = '/usr/local/nginx/config/'
config = nginxparser.NginxConfig.load(nginx_config_path)

url = 'http://your.domain.name/path/filename.cgi?param=value'
upstream_list = config.getUpstreamsByUrl(url)
upstream_host_list = config.getHostsByUrl(url)

ip = '1.1.1.1'
upstream_related_ip_list = config.getHostsByHost(ip)

```