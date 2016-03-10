#!/usr/bin/python3
# -*- coding: utf8 -*-

import collections
import argparse
import datetime
import zerod
import sys
import os


class ZeroControl:
    APP_VERSION = '2.2.0'
    LEGACY_DEFAULT_SCOPE = 'zero'

    def __init__(self, server, human=False, verbosity=0):
        self.client = zerod.ZeroClient(server)
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

    def _fmt_ts(self, ts):
        if self.human:
            return datetime.datetime.fromtimestamp(ts).strftime('%Y.%m.%d %H:%M:%S')
        else:
            return ts

    @staticmethod
    def _ring_info_add(src, dst):
        if not dst:
            for what in ('packets', 'traffic'):
                dst[what] = dict()
                for dir in ('down', 'up'):
                    dst[what][dir] = dict()
                    for type in ('total', 'client', 'local', 'non_client'):
                        dst[what][dir][type] = dict()
                        for action in ('total', 'pass', 'drop'):
                            dst[what][dir][type][action] = {"count": 0, "speed": 0}

        for what in ('packets', 'traffic'):
            for dir in ('down', 'up'):
                for type in ('client', 'local', 'non_client'):
                    for action in ('pass', 'drop'):
                        src_info = src[what][dir][type][action]
                        dst_info = dst[what][dir][type][action]

                        dst_info['count'] += src_info['count']
                        dst_info['speed'] += src_info['speed']

                        if 'avg_ppt' in src_info:
                            if 'avg_ppt' not in dst_info:
                                dst_info['avg_ppt'] = src_info['avg_ppt']
                            else:
                                dst_info['avg_ppt'] = (dst_info['avg_ppt'] + src_info['avg_ppt']) // 2

                        dst[what][dir]['total']['total']['count'] += src_info['count']
                        dst[what][dir]['total']['total']['speed'] += src_info['speed']

    def _print_ring_stats(self, ring):
        for dir in ('down', 'up'):
            if 'total' in ring['packets'][dir]:
                text = " {:<20} {:>15}pkt\t{:>15}pps\t{:>15}B\t{:>15}bps".format(
                    '{}_total'.format(dir),
                    self._fmt(ring['packets'][dir]['total']['total']['count'], 1000),
                    self._fmt(ring['packets'][dir]['total']['total']['speed'], 1000),
                    self._fmt(ring['traffic'][dir]['total']['total']['count'], 1024),
                    self._fmt(ring['traffic'][dir]['total']['total']['speed'] * 8, 1024)
                )
                print(text)
            for type in ('client', 'local', 'non_client'):
                for action in ('pass', 'drop'):
                    text = " {:<20} {:>15}pkt\t{:>15}pps\t{:>15}B\t{:>15}bps".format(
                        '{}_{}_{}'.format(dir, type, action),
                        self._fmt(ring['packets'][dir][type][action]['count'], 1000),
                        self._fmt(ring['packets'][dir][type][action]['speed'], 1000),
                        self._fmt(ring['traffic'][dir][type][action]['count'], 1024),
                        self._fmt(ring['traffic'][dir][type][action]['speed'] * 8, 1024),
                    )
                    if 'avg_ppt' in ring['packets'][dir][type][action]:
                        text = "{}\t{:>15}".format(text, ring['packets'][dir][type][action]['avg_ppt'])
                    print(text)

    def show_stats(self):
        stats = self.client.get_stats()

        if stats['code'] != 'success':
            print(stats['code'])
            return

        text = \
            "Start time: {}\n" \
            "Sessions count: {}\n" \
            "Unauth sessions count: {}\n" \
            "Clients count: {}\n"
        print(text.format(
            self._fmt_ts(stats['start_time']),
            stats['sessions']['total'],
            stats['sessions']['unauth'],
            stats['clients']['total']
        ))

        if self.human:
            print("\t\t\t\tPkt\t\t\tPkt speed\t\tTraffic\t\tTraffic speed")

        if_pair = dict()
        total_if = dict()
        total = dict()
        for i, ring in enumerate(stats['rings']):
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
                if (i + 1 == len(stats['rings'])) or (if_pair['lan'] != stats['rings'][i + 1]['lan']):
                    print("{}-{} total:".format(if_pair['lan'], if_pair['wan']))
                    self._print_ring_stats(total_if)
                    # mark as empty
                    total_if = dict()

        if self.human or self.verbosity >= 1:
            print("Total:")

        self._print_ring_stats(total)

    def show_scopes(self):
        rep = self.client.get_scopes()
        if rep['code'] != 'success':
            print(rep['code'])
            return

        for scope in rep['scopes']:
            print(scope)

    def scope_show(self, scope):
        rep = self.client.get_scope(scope)

        if rep['code'] != 'success':
            print(rep['code'])
        else:
            config = collections.OrderedDict(sorted(rep['config'].items(), key=lambda t: t[0]))
            for item, value in config.items():
                print('{} = {}'.format(item, value))

    def client_show(self, scope, client):
        rep = self.client.get_client(scope, client)

        if rep['code'] != 'success':
            print(rep['code'])
            return

        if self.human:
            print("Client config:")

        for rule in rep['rules']:
            print(rule)

    def client_update(self, scope, client, rules):
        if not rules:
            raise RuntimeError("No rules specified")
        rep = self.client.update_client(scope, client, rules)
        print(rep['code'])

    def client_delete(self, scope, client):
        rep = self.client.delete_client(scope, client)
        print(rep['code'])

    def session_show(self, scope, ip):
        rep = self.client.get_session(scope, ip)

        if rep['code'] != 'success':
            print(rep['code'])
            return

        print("Create time: {}".format(self._fmt_ts(rep['create_time'])))
        print("User id: {}".format(rep['user_id']))
        print("Last activity: {}".format(self._fmt_ts(rep['last_activity'])))
        print("Last authorization: {}".format(self._fmt_ts(rep['last_authorization'])))
        print("Last accounting: {}".format(self._fmt_ts(rep['last_accounting'])))
        print("Download traffic: {}B".format(self._fmt(rep['traffic_down'], 1024)))
        print("Upload traffic: {}B".format(self._fmt(rep['traffic_up'], 1024)))
        print("Timeout: {} secs".format(rep['timeout']))
        print("Idle timeout: {} secs".format(rep['idle_timeout']))
        print("Accounting interval: {} secs".format(rep['accounting_interval']))
        if 'mac' in rep:
            print("DHCP lease end: {}".format(self._fmt_ts(rep['dhcp_lease_end'])))
            print("H/W address: {}".format(rep['mac']))

    def session_delete(self, scope, ip):
        rep = self.client.delete_session(scope, ip)
        print(rep['code'])

    def monitor(self, filters):
        rep = self.client.monitor(filters)

        if rep['code'] != 'success':
            print(rep['code'])
        else:
            while True:
                data = self.client.conn.recv(1024)
                os.write(sys.stdout.fileno(), data)

    def dump_counters(self):
        rep = self.client.dump_counters()
        print(rep['code'])

    @staticmethod
    def rules_help():
        text = \
            "Client rules:\n" \
            "\tbw.<speed>[K|M|G]Bit.<up|down> - bandwidth limit\n" \
            "\tports.<allow|deny>.<tcp|udp>.<port1>[.<port2>] - add port rule\n" \
            "\trmports.<allow|deny>.<tcp|udp>.<port1>[.<port2>] - remove port rule\n" \
            "\tfwd.<tcp|udp>.<port>.<ip>[:<port>] - add forwarding rule\n" \
            "\trmfwd.<tcp|udp>.<port> - remove forwarding rule\n" \
            "\tdeferred.<seconds>.<rule> - apply deferred rule after given timeout\n" \
            "\trmdeferred - remove all deferred rules\n"
        print(text)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()

    parser.add_argument('-s', '--server', metavar='HOST[:PORT]', help='server address and port',
                        default="localhost:1050")
    parser.add_argument('-H', '--human', help='human readable output format', action='store_true')
    parser.add_argument('-v', '--verbose', help='increase verbosity level', action='count', default=0)
    parser.add_argument('-V', '--version', help='show version', action='version',
                        version='%(prog)s {}'.format(ZeroControl.APP_VERSION))

    # SHOW
    parser_show = subparsers.add_parser('show', help='show manipulator')
    show_subparsers = parser_show.add_subparsers()

    # show scopes
    parser_show_scopes = show_subparsers.add_parser('scopes', help='show scopes')
    parser_show_scopes.set_defaults(func=lambda app, args: app.show_scopes())

    # show stats
    parser_show_stats = show_subparsers.add_parser('stats', help='show stats')
    parser_show_stats.set_defaults(func=lambda app, args: app.show_stats())

    # SCOPE
    parser_scope = subparsers.add_parser('scope', help='scope manipulator')
    parser_scope.add_argument('scope', metavar='SCOPE', type=str, help='name of scope')
    scope_subparsers = parser_scope.add_subparsers()

    # scope show
    parser_scope_show = scope_subparsers.add_parser('show', help='show scope')
    parser_scope_show.set_defaults(func=lambda app, args: app.scope_show(args.scope))

    # scope update
    # parser_scope_update = scope_subparsers.add_parser('update', help='update scope')
    # parser_scope_update.add_argument('rule', metavar='RULE', type=str, help='configuration rule', nargs='+')
    # parser_scope_update.set_defaults(func=lambda app, args: app.scope_update(args.scope, args.rule))

    # SESSION
    parser_session = scope_subparsers.add_parser('session', help='session manipulator')
    parser_session.add_argument('ip', metavar='IP', type=str, help='IP address of session')
    session_subparsers = parser_session.add_subparsers()

    # session show
    parser_session_show = session_subparsers.add_parser('show', help='show session')
    parser_session_show.set_defaults(func=lambda app, args: app.session_show(args.scope, args.ip))

    # session delete
    parser_session_delete = session_subparsers.add_parser('delete', help='delete session')
    parser_session_delete.set_defaults(func=lambda app, args: app.session_delete(args.scope, args.ip))

    # CLIENT
    parser_client = scope_subparsers.add_parser('client', help='client manipulator')
    parser_client.add_argument('ip', metavar='IP|ID', type=str, help='IP address or ID of client')
    client_subparsers = parser_client.add_subparsers()

    # client show
    parser_client_show = client_subparsers.add_parser('show', help='show client')
    parser_client_show.set_defaults(func=lambda app, args: app.client_show(args.scope, args.ip))

    # client update
    parser_client_update = client_subparsers.add_parser('update', help='update client')
    parser_client_update.add_argument('rule', metavar='RULE', type=str, help='configuration rule', nargs='+')
    parser_client_update.set_defaults(func=lambda app, args: app.client_update(args.scope, args.ip, args.rule))

    # client delete
    parser_client_delete = client_subparsers.add_parser('delete', help='delete client')
    parser_client_delete.set_defaults(func=lambda app, args: app.client_delete(args.scope, args.ip))

    # RULES HELP
    parser_rules = subparsers.add_parser('rules-help', help='rules help')
    parser_rules.set_defaults(func=lambda app, args: app.rules_help())

    # MONITOR
    parser_monitor = subparsers.add_parser('monitor', help='monitor manipulator')
    parser_monitor.add_argument('filter', metavar='FILTER', type=str,
                                help='traffic monitoring with optional BPF filter (ex. vlan or ip)', nargs='*')
    parser_monitor.set_defaults(func=lambda app, args: app.monitor(args.filter))

    # DEBUG
    parser_debug = subparsers.add_parser('debug', help='debug manipulator (ONLY FOR DEBUG BUILDS)')
    debug_subparsers = parser_debug.add_subparsers()

    # dump counters
    parser_dump_counters = debug_subparsers.add_parser('dump-counters', help='dump traffic counters')
    parser_dump_counters.set_defaults(func=lambda app, args: app.dump_counters())

    args = parser.parse_args()
    app = ZeroControl(args.server, human=args.human, verbosity=args.verbose)

    if 'func' not in args:
        print('Incomplete command')
    else:
        args.func(app, args)
