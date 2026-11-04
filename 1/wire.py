"""Raw JSON over TCP, compatible with the supplied examples.
TCP can split/combine JSON objects, so buffer and parse one object at a time.
"""
import json
import logging
from pathlib import Path

MAX_JSON_BYTES = 1_048_576


class ProtocolError(ValueError):
    pass


class PeerError(ProtocolError):
    pass


class JsonChannel:
    def __init__(self, sock, transcript=None):
        self.sock = sock
        self.buffer = b''
        self.decoder = json.JSONDecoder()
        self.transcript = Path(transcript) if transcript else None
        if self.transcript:
            self.transcript.parent.mkdir(parents=True, exist_ok=True)
            self.transcript.write_text('', encoding='utf-8')

    def record(self, message, direction):
        encoded = json.dumps(message, ensure_ascii=True)
        logging.info('%s %s', direction, encoded)
        if self.transcript:
            with self.transcript.open('a', encoding='utf-8') as stream:
                stream.write(encoded + '\n')

    def send(self, message):
        encoded = json.dumps(message, ensure_ascii=True).encode('ascii')
        if len(encoded) > MAX_JSON_BYTES:
            raise ProtocolError('JSON message is too large')
        self.sock.sendall(encoded)
        self.record(message, 'Sent:')

    def receive(self):
        while True:
            self.buffer = self.buffer.lstrip()
            if self.buffer and not self.buffer.startswith(b'{'):
                raise ProtocolError('expected a JSON object')
            try:
                text = self.buffer.decode('utf-8')
                message, end = self.decoder.raw_decode(text)
            except (UnicodeDecodeError, json.JSONDecodeError):
                chunk = self.sock.recv(4096)
                if not chunk:
                    raise ProtocolError('peer closed before a complete JSON message')
                self.buffer += chunk
                if len(self.buffer) > MAX_JSON_BYTES:
                    raise ProtocolError('JSON message is too large')
                continue
            self.buffer = text[end:].encode('utf-8')
            self.record(message, 'Received:')
            return message


def expect(message, opcode, kind=None):
    if type(message.get('opcode')) is not int:
        raise ProtocolError('opcode must be an integer')
    if message.get('opcode') == 3:
        raise PeerError(str(message.get('error', 'unspecified peer error')))
    if message.get('opcode') != opcode or (kind is not None and message.get('type') != kind):
        raise ProtocolError('unexpected opcode or type')
    return message


def parameters(message):
    value = message.get('parameter')
    if not isinstance(value, dict):
        raise ProtocolError('parameter must be a JSON object')
    return value


def send_error(channel, reason):
    try:
        channel.send({'opcode': 3, 'error': reason})
    except OSError:
        logging.warning('Connection closed before the error could be sent')
