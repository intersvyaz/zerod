# -*- coding: utf8 -*-

import random
import socket
import struct
import bson


class ZeroClient:
    MAGIC = 0x1234
    PROTO_VER = 2
    DEFAULT_PORT = 1050

    def __init__(self, server):
        if ':' in server:
            (host, port) = server.split(':')
            self.server = (host, int(port))
        else:
            self.server = (server, self.DEFAULT_PORT)
        self._conn = None

    @property
    def conn(self):
        if not self._conn:
            self._conn = self._connect(self.server)
        return self._conn

    @staticmethod
    def _connect(server):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(server)
        return sock

    @classmethod
    def _read_packet(cls, sock):
        data = b''
        while len(data) < 2:
            data += sock.recv(2 - len(data))
        magic = socket.ntohs(struct.unpack('H', data)[0])

        if magic != cls.MAGIC:
            raise RuntimeError('Invalid magic header (0x{:04x})'.format(magic))

        data = b''
        while len(data) < 4:
            data += sock.recv(4 - len(data))
        bson_length = struct.unpack('I', data)[0]

        # document length is required for decoding
        while len(data) < bson_length:
            data += sock.recv(bson_length - len(data))

        return bson.decode_all(data)[0]

    @classmethod
    def _write_packet(cls, sock, data):
        data['version'] = cls.PROTO_VER
        data['cookie'] = random.randint(1, bson.MAX_INT32)
        magic = struct.pack('H', socket.htons(cls.MAGIC))
        packet = b''.join((magic, bson.BSON.encode(data)))
        return sock.sendall(packet)

    def get_stats(self):
        self._write_packet(self.conn, {'action': 'show_stats'})
        return self._read_packet(self.conn)

    def get_scopes(self):
        self._write_packet(self.conn, {'action': 'show_scopes'})
        return self._read_packet(self.conn)

    def get_scope(self, scope):
        self._write_packet(self.conn, {'action': 'scope_show', 'scope': scope})
        return self._read_packet(self.conn)

    def update_scope(self, scope, rules):
        self._write_packet(self.conn, {'action': 'scope_update', 'scope': scope, 'rules': rules})
        return self._read_packet(self.conn)

    def get_client(self, scope, client):
        request = {'action': 'client_show', 'scope': scope}
        if client.isdigit():
            request['id'] = int(client)
        else:
            request['ip'] = client
        self._write_packet(self.conn, request)
        return self._read_packet(self.conn)

    def update_client(self, scope, client, rules):
        request = {'action': 'client_update', 'scope': scope, 'rules': rules}
        if client.isdigit():
            request['id'] = int(client)
        else:
            request['ip'] = client
        self._write_packet(self.conn, request)
        return self._read_packet(self.conn)

    def delete_client(self, scope, client):
        request = {'action': 'client_delete', 'scope': scope}
        if client.isdigit():
            request['id'] = int(client)
        else:
            request['ip'] = client
        self._write_packet(self.conn, request)
        return self._read_packet(self.conn)

    def get_session(self, scope, ip):
        self._write_packet(self.conn, {'action': 'session_show', 'scope': scope, 'ip': ip})
        return self._read_packet(self.conn)

    def delete_session(self, scope, ip):
        self._write_packet(self.conn, {'action': 'session_delete', 'scope': scope, 'ip': ip})
        return self._read_packet(self.conn)

    def monitor(self, filters):
        self._write_packet(self.conn, {'action': 'monitor', 'filter': ' '.join(filters)})
        return self._read_packet(self.conn)

    def dump_counters(self):
        self._write_packet(self.conn, {'action': 'dump_counters'})
        return self._read_packet(self.conn)
