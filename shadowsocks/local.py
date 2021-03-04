#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2012-2015 clowwindy
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from __future__ import absolute_import, division, print_function, \
    with_statement

import socket

import sys
import os
import logging
import signal

from shadowsocks.common import InnoProto, InnoEnv

if __name__ == '__main__':
    import inspect
    file_path = os.path.dirname(os.path.realpath(inspect.getfile(inspect.currentframe())))
    sys.path.insert(0, os.path.join(file_path, '../'))

from shadowsocks import shell, daemon, eventloop, tcprelay, udprelay, asyncdns, common, encrypt, obfs


def inno_auth(config, tcp_server):
    """
    :type config: dict
    :type tcp_server: tcprelay.TCPRelay
    :rtype: bytes
    """
    server_addr = config['server']
    server_port = config['server_port']

    passphrase = InnoEnv.local_passphrase

    encryptor = encrypt.Encryptor(config['password'], config['method'], None, True)
    obfuscate = obfs.obfs(config['obfs'])

    server_info = obfs.server_info(tcp_server.obfs_data)
    server_info.host = config['server']
    server_info.port = tcp_server._listen_port
    server_info.protocol_param = ''
    server_info.obfs_param = config['obfs_param']
    server_info.iv = encryptor.cipher_iv
    server_info.recv_iv = b''
    server_info.key_str = common.to_bytes(config['password'])
    server_info.key = encryptor.cipher_key
    server_info.head_len = 30
    obfuscate.set_server_info(server_info)

    # 组装请求内容
    request = InnoProto.pack_auth_data(passphrase)
    request = encryptor.encrypt(request)
    request = obfuscate.client_encode(request)

    # 发送请求
    logging.debug('Inno: send auth request with passphrase %s', common.to_str(passphrase))
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((server_addr, server_port))
    sock.send(request)
    resp = sock.recv(1024)
    sock.close()
    logging.debug('Inno: auth response %s', resp.hex())

    # 返回 token
    token = InnoProto.parse_auth_result(resp)
    if not token:
        logging.debug('Inno: auth failed with response %s', resp.hex())
        raise RuntimeError('auth fail')
    return token


def main():
    shell.check_python()

    # fix py2exe
    if hasattr(sys, "frozen") and sys.frozen in \
            ("windows_exe", "console_exe"):
        p = os.path.dirname(os.path.abspath(sys.executable))
        os.chdir(p)

    config = shell.get_config(True)

    if not config.get('dns_ipv6', False):
        asyncdns.IPV6_CONNECTION_SUPPORT = False

    daemon.daemon_exec(config)
    logging.info("local start with protocol[%s] password [%s] method [%s] obfs [%s] obfs_param [%s]" %
            (config['protocol'], config['password'], config['method'], config['obfs'], config['obfs_param']))

    try:
        logging.info("starting local at %s:%d" %
                     (config['local_address'], config['local_port']))

        InnoEnv.init(config)

        dns_resolver = asyncdns.DNSResolver()
        tcp_server = tcprelay.TCPRelay(config, dns_resolver, True)
        udp_server = udprelay.UDPRelay(config, dns_resolver, True)
        loop = eventloop.EventLoop()
        dns_resolver.add_to_loop(loop)
        tcp_server.add_to_loop(loop)
        udp_server.add_to_loop(loop)

        def handler(signum, _):
            logging.warn('received SIGQUIT, doing graceful shutting down..')

            udp_server.inno_send_disconnect()

            tcp_server.close(next_tick=True)
            udp_server.close(next_tick=True)
        signal.signal(getattr(signal, 'SIGQUIT', signal.SIGTERM), handler)

        def int_handler(signum, _):
            udp_server.inno_send_disconnect()

            sys.exit(1)
        signal.signal(signal.SIGINT, int_handler)

        daemon.set_user(config.get('user', None))

        # InnoSSR 获取 token
        token = inno_auth(config, tcp_server)
        logging.info('Inno: get token %s', token.hex())
        InnoEnv.local_token = token

        loop.run()
    except Exception as e:
        shell.print_exception(e)
        sys.exit(1)

if __name__ == '__main__':
    main()
