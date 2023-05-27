# -*- coding: UTF-8 -*-
import argparse
import yaml

from pathlib import Path

from tls_client.lib.client import TLSClient


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument("--host", type=str)
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--config", type=str, default=Path.cwd()/"src"/"tls_client"/"config"/"config.yaml")
    parser.add_argument("--version", type=int, default=2)
    
    parser.add_argument("-M", type=str, default="GET")
    parser.add_argument("-P", type=str, default="/")
    parser.add_argument("-H", type=str, required=False, nargs="*")
    parser.add_argument("-D", type=str, default="")
    
    return parser.parse_args()


def main():
    def make_http(method="GET", path="/", headers=[], data=""):
        headers_formatted = ""
        if headers:
            headers_formatted = "\r\n".join(headers)
        http_request = f"{method} {path} HTTP/1.1\r\n{headers_formatted}\r\n{data}\r\n\r\n"
        return http_request
    
    args = parse_args()

    http_msg = make_http(method=args.M, path=args.P, headers=args.H, data=args.D)

    with open(args.config) as f:
        config_dict = yaml.safe_load(f)

    client = TLSClient()
    client.init_from_config(config_dict)
    with client.connect(args.host, args.port, version=args.version):
        client.send(http_msg.encode("UTF-8"))
        print(client.recv())
