#!/usr/bin/python3
# -*- coding: utf8 -*-

import argparse
import os
import socket
import struct
import datetime
import random
import bson
import sys
from contextlib import closing


class ZeroControl:
    APP_VERSION = '0.16.6'
    MAGIC = 0x1234
    PROTO_VER = 1
    DEFAULT_PORT = 1050

    def __init__(self, server, human=False, verbosity=0):
        if ':' in server:
            (host, port) = server.split(':')
            self.server = (host, int(port))
        else:
            self.server = (server, self.DEFAULT_PORT)
        self.human = human
        self.verbosity = verbosity

    def _fmt(self, value, base):
        prefix = " KMGTPEZ"

        if self.human:
            i = 0
            value = float(value)

            while value >= base:
                i += 1
                value /= base

            return '{:.2f} {}'.format(value, prefix[i])
        else:
            return '{} '.format(value)

    def _connect(self, server):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(server)
        return sock

    def _read_packet(self, sock):
        while True:
            magic = sock.recv(2)
            if len(magic) >= 2:
                break
        magic = socket.ntohs(struct.unpack('H', magic)[0])

        if magic != self.MAGIC:
            raise RuntimeError('Invalid magic header')

        while True:
            data = sock.recv(4)
            if len(data) >= 4:
                break
        bson_length = struct.unpack('I', data)[0]

        while len(data) < bson_length:
            data = b''.join((data, sock.recv(bson_length - len(data))))

        return bson.decode_all(data)

    def _write_packet(self, sock, data):
        data['version'] = self.PROTO_VER
        data['cookie'] = random.randint(1, bson.MAX_INT32)
        magic = struct.pack('H', socket.htons(self.MAGIC))
        packet = b''.join((magic, bson.BSON.encode(data)))
        return sock.sendall(packet)

    def _ring_info_add(self, src, dst):
        if not dst:
            for what in ('packets', 'traffic'):
                dst[what] = dict()
                for direction in ('down', 'up'):
                    dst[what][direction] = {
                        "all": {"count": 0, "speed": 0},
                        "passed": {"count": 0, "speed": 0},
                        "client": {"count": 0, "speed": 0}
                    }

        for what in ('packets', 'traffic'):
            for direction in ('down', 'up'):
                for tp in ('all', 'passed', 'client'):
                    dst[what][direction][tp]['count'] += src[what][direction][tp]['count']
                    dst[what][direction][tp]['speed'] += src[what][direction][tp]['speed']

    def _print_ring_stats(self, ring):
        for direction in ('down', 'up'):
            for tp in ('all', 'passed', 'client'):
                print(" {:<14} {:>15}pkt\t{:>15}pps\t{:>15}B\t{:>15}bps".format(
                    '{} {}'.format(direction, tp),
                    self._fmt(ring['packets'][direction][tp]['count'], 1000),
                    self._fmt(ring['packets'][direction][tp]['speed'], 1000),
                    self._fmt(ring['traffic'][direction][tp]['count'], 1024),
                    self._fmt(ring['traffic'][direction][tp]['speed'] * 8, 1024)
                ))

    def show_stats(self):
        with closing(self._connect(self.server)) as conn:
            self._write_packet(conn, {'action': 'show_stats'})
            packet = self._read_packet(conn)[0]

            if packet['code'] != 'success':
                raise RuntimeError('Invalid return code: {}'.format(packet['code']))

            text = \
                "Server stats:\n" \
                "Sessions count: {}\n" \
                "Unauth sessions count: {}\n" \
                "Clients count: {}\n" \
                "Non-client speed down: {}bps (limit: {}bps)\n" \
                "Non-client speed up: {}bps (limit: {}bps)\n"
            print(text.format(
                packet['sessions']['total'],
                packet['sessions']['unauth'],
                packet['clients']['total'],
                self._fmt(packet['non_clients']['speed']['down'] * 8, 1024),
                self._fmt(packet['non_clients']['max_bandwidth']['down'] * 8, 1024),
                self._fmt(packet['non_clients']['speed']['up'] * 8, 1024),
                self._fmt(packet['non_clients']['max_bandwidth']['up'] * 8, 1024)
            ))

            if self.human:
                print("\t\t\tPkt\t\t\tPkt speed\t\tTraffic\t\tTraffic speed")

            if_pair = dict()
            total_if = dict()
            total = dict()
            for i, ring in enumerate(packet['rings']):
                if 'lan' not in total_if:
                    if_pair['lan'] = ring['lan']
                    if_pair['wan'] = ring['wan']

                self._ring_info_add(ring, total)
                self._ring_info_add(ring, total_if)

                if self.verbosity >= 2:
                    print('{}-{} ring{}:'.format(if_pair['lan'], if_pair['wan'], ring['ring_id']))
                    self._print_ring_stats(ring)

                if self.verbosity >= 1:
                    # interface pair changed or last in list
                    if (i + 1 == len(packet['rings'])) or (if_pair['lan'] != packet['rings'][i+1]['lan']):
                        print("{}-{} total:".format(if_pair['lan'], if_pair['wan']))
                        self._print_ring_stats(total_if)
                        # mark as empty
                        total_if = dict()

            if self.human or self.verbosity >= 1:
                print("Total:")

            self._print_ring_stats(total)

    def show_upstreams(self):
        with closing(self._connect(self.server)) as conn:
            self._write_packet(conn, {'action': 'upstream_show'})
            packet = self._read_packet(conn)[0]

            if packet['code'] != 'success':
                raise RuntimeError('Invalid return code: {}'.format(packet['code']))

            if self.human:
                print("Upstream stats:")
                print("Upstream\t\tSpeed down\t\tSpeed up\t\tP2P limit down\t\tP2P limit up")

            for i, upstream in enumerate(packet['upstreams']):
                print("{}\t\t{:>14}bps\t{:>14}bps\t{:>14}bps\t{:>14}bps".format(
                    i,
                    self._fmt(upstream['speed']['down']*8, 1024),
                    self._fmt(upstream['speed']['up']*8, 1024),
                    self._fmt(upstream['p2p_bw_limit']['down']*8, 1024),
                    self._fmt(upstream['p2p_bw_limit']['up']*8, 1024)
                ))

    def show_client(self, client):
        with closing(self._connect(self.server)) as conn:
            request = {'action': 'client_show'}
            if client.isdigit():
                request['id'] = int(client)
            else:
                request['ip'] = client
            self._write_packet(conn, request)
            packet = self._read_packet(conn)[0]

            if packet['code'] != 'success':
                raise RuntimeError('Invalid return code: {}'.format(packet['code']))

            if self.human:
                print("Client config:")

            for rule in packet['rules']:
                print(rule)

    def update_client(self, client, rules):
        if not rules:
            raise RuntimeError('You must specify at least one rule!')

        with closing(self._connect(self.server)) as conn:
            request = {'action': 'client_update', 'rules': rules}
            if client.isdigit():
                request['id'] = int(client)
            else:
                request['ip'] = client
            self._write_packet(conn, request)
            packet = self._read_packet(conn)[0]

            if packet['code'] != 'success':
                raise RuntimeError('Invalid return code: {}'.format(packet['code']))
            else:
                print(packet['code'])

    def show_session(self, ip):
        with closing(self._connect(self.server)) as conn:
            self._write_packet(conn, {'action': 'session_show', 'ip': ip})
            packet = self._read_packet(conn)[0]

            if packet['code'] != 'success':
                raise RuntimeError('Invalid return code: {}'.format(packet['code']))

            print("Last activity: {}".format(datetime.datetime.fromtimestamp(packet['last_activity']).strftime('%Y.%m.%d %H:%M:%S')))
            print("Last authorization: {}".format(datetime.datetime.fromtimestamp(packet['last_authorization']).strftime('%Y.%m.%d %H:%M:%S')))
            print("Last accounting: {}".format(datetime.datetime.fromtimestamp(packet['last_accounting']).strftime('%Y.%m.%d %H:%M:%S')))
            print("User id: {}".format(packet['user_id']))
            print("Download traffic: {}B".format(self._fmt(packet['traffic_down'], 1024)))
            print("Upload traffic: {}B".format(self._fmt(packet['traffic_up'], 1024)))
            print("Max duration: {} secs".format(packet['max_duration']))
            print("Accounting interval: {} secs".format(packet['accounting_interval']))

    def delete_session(self, ip):
        with closing(self._connect(self.server)) as conn:
            self._write_packet(conn, {'action': 'session_delete', 'ip': ip})
            packet = self._read_packet(conn)[0]

            if packet['code'] != 'success':
                raise RuntimeError('Invalid return code: {}'.format(packet['code']))
            else:
                print(packet['code'])

    def monitor(self, filters):
        with closing(self._connect(self.server)) as conn:
            self._write_packet(conn, {'action': 'monitor', 'filter': ' '.join(filters)})
            packet = self._read_packet(conn)[0]

            if packet['code'] != 'success':
                raise RuntimeError('Invalid return code: {}'.format(packet['code']))
            else:
                while True:
                    data = conn.recv(1024)
                    os.write(sys.stdout.fileno(), data)

    def reconfigure(self, rules):
        if not rules:
            raise RuntimeError('You must specify at least one rule!')

        with closing(self._connect(self.server)) as conn:
            conn = self._connect(self.server)
            self._write_packet(conn, {'action': 'reconfigure', 'rules': rules})
            packet = self._read_packet(conn)[0]

            if packet['code'] != 'success':
                raise RuntimeError('Invalid return code: {}'.format(packet['code']))
            else:
                print(packet['code'])

    def dump_counters(self):
        with closing(self._connect(self.server)) as conn:
            self._write_packet(conn, {'action': 'dump_counters'})
            packet = self._read_packet(conn)[0]

            if packet['code'] != 'success':
                raise RuntimeError('Invalid return code: {}'.format(packet['code']))
            else:
                print(packet['code'])

    def rules_help(self):
        text = \
            "Client rules:\n" \
            "\tbw.<speed>KBit.<up|down> - bandwidth limit\n" \
            "\tp2p_policer.<0|1> - p2p policer\n" \
            "\tports.<allow|deny>.<tcp|udp>.<port1>[.<port2>] - add port rule\n" \
            "\trmports.<allow|deny>.<tcp|udp>.<port1>[.<port2>] - remove port rule\n" \
            "\tfwd.<tcp|udp>.<port>.<ip>[:<port>] - add forwarding rule\n" \
            "\trmfwd.<tcp|udp>.<port> - remove forwarding rule\n" \
            "\tdeferred.<seconds>.<rule> - apply deferred rule after given timeout\n" \
            "Server rules:\n" \
            "\tupstream_bw.<id>.<speed>Kbit.<up|down> - upstream p2p bandwidth limit\n" \
            "\tnon_client_bw.<speed>Kbit.<up|down> - non-client bandwidth limit"
        print(text)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('-s', '--server', metavar='HOST[:PORT]', help='server address and port',
                        default="localhost:1050")
    parser.add_argument('-H', '--human', help='print numbers in in human readable format', action='store_true')
    parser.add_argument('--rules', metavar='RULE', help='define rule for client or server', nargs='*')
    parser.add_argument('-v', '--verbose', help='increase verbosity level', action='count', default=0)

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-V', '--version', action='version', version='%(prog)s {}'.format(ZeroControl.APP_VERSION))
    group.add_argument('--show-stats', help='show server info', action='store_true')
    group.add_argument('--show-upstreams', help='show upstreams info', action='store_true')
    group.add_argument('-C', '--show-client', metavar='IP|ID', help='show client info')
    group.add_argument('--update-client', metavar='IP|ID', help='update client configuration')
    group.add_argument('-S', '--show-session', metavar='IP', help='show session info')
    group.add_argument('--delete-session', metavar='IP', help='delete session')
    group.add_argument('-m', '--monitor', metavar='FILTER',
                       help='traffic monitoring with optional bpf-like filter (ex. vlan or ip)', nargs='*')
    group.add_argument('-R', '--reconfigure', help='modify server configuration', action='store_true')
    group.add_argument('--rules-help', help='show rules help', action='store_true')
    group.add_argument('--dump-counters', help='dump debug counters (ONLY FOR DEBUG BUILDS)', action='store_true')

    args = parser.parse_args()
    app = ZeroControl(args.server, human=args.human, verbosity=args.verbose)

    if args.show_stats:
        app.show_stats()

    elif args.show_upstreams:
        app.show_upstreams()

    elif args.show_client:
        app.show_client(args.show_client)

    elif args.update_client:
        app.update_client(args.update_client, args.rules)

    elif args.show_session:
        app.show_session(args.show_session)

    elif args.delete_session:
        app.delete_session(args.delete_session)

    elif type(args.monitor) is list:
        app.monitor(args.monitor)

    elif args.reconfigure:
        app.reconfigure(args.rules)

    elif args.rules_help:
        app.rules_help()

    elif args.dump_counters:
        app.dump_counters()

    else:
        raise RuntimeError('invalid action')
