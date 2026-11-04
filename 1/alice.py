"""Alice/client: Protocols I, II, III and IV."""
import argparse
import logging
import secrets
import socket
from crypto_math import (decrypt_message, dh_aes_key, dh_parameter_error,
                         dh_private, dh_shared, encrypt_message, mod_pow,
                         rsa_encrypt_key, verify_rsa_key)
from wire import JsonChannel, PeerError, ProtocolError, expect, parameters, send_error


def session(channel, protocol, message, local='Alice', peer='Bob'):
    channel.send({'opcode': 0, 'type': protocol})
    if protocol == 'RSAKey':
        reply = expect(channel.receive(), 0, 'RSAKey')
        params = parameters(reply)
        p, q = params.get('p'), params.get('q')
        e, d = reply.get('public'), reply.get('private')
        checks = verify_rsa_key(p, q, e, d)
        print(f'RSA key: p={p}, q={q}, e={e}, d={d}', flush=True)
        for name, passed in checks.items():
            print(f"  {name}: {'PASS' if passed else 'FAIL'}", flush=True)
        if not all(checks.values()):
            raise ProtocolError('incorrect RSA keypair')
        print('RSAKey verification: PASS', flush=True)
        return

    reply = expect(channel.receive(), 1, protocol)
    params = parameters(reply)
    if protocol == 'RSA':
        key = secrets.token_bytes(32)
        encrypted = rsa_encrypt_key(key, reply.get('public'), params.get('n'))
        channel.send({'opcode': 2, 'type': 'RSA', 'encrypted_key': encrypted})
    else:
        p, g = params.get('p'), params.get('g')
        error = dh_parameter_error(p, g)
        if error:
            raise ProtocolError(error)
        private = dh_private(p)
        public = mod_pow(g, private, p)
        key = dh_aes_key(dh_shared(reply.get('public'), private, p))
        channel.send({'opcode': 1, 'type': 'DH', 'public': public})

    reply = expect(channel.receive(), 2, 'AES')
    plain = decrypt_message(key, reply.get('encryption'))
    print(f'{peer} -> {local} (decrypted): {plain}', flush=True)
    channel.send({'opcode': 2, 'type': 'AES',
                  'encryption': encrypt_message(key, message)})
    print(f'{protocol} exchange: PASS', flush=True)


def run(addr, port, protocol='RSA', message='Hello from Alice', timeout=30.0,
        transcript=None, serve=False):
    if timeout <= 0:
        raise ValueError('timeout must be positive')
    with socket.create_connection((addr, port), timeout=timeout) as conn:
        conn.settimeout(timeout)
        channel = JsonChannel(conn, transcript)
        logging.info('Alice is connected to %s:%s', addr, port)
        try:
            if serve:
                from bob import session as responder_session
                responder_session(channel, message, local='Alice', peer='Bob')
            else:
                session(channel, protocol, message)
        except PeerError:
            raise
        except (ValueError, KeyError, TypeError) as exc:
            send_error(channel, str(exc))
            raise ProtocolError(str(exc)) from exc


def command_line_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-a', '--addr', required=True, help="Bob's IP address")
    parser.add_argument('-p', '--port', required=True, type=int)
    parser.add_argument('-t', '--type', '--protocol', dest='protocol',
                        choices=['RSAKey', 'RSA', 'DH'], default='RSA')
    parser.add_argument('-m', '--message', default='Hello from Alice')
    parser.add_argument('-l', '--log', default='INFO',
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'])
    parser.add_argument('--timeout', type=float, default=30.0)
    parser.add_argument('--transcript', help='Save exchanged JSON, one session per file')
    parser.add_argument('--serve', action='store_true',
                        help='Optional reversed role: connect, then answer a request from Bob')
    return parser.parse_args()


def main():
    args = command_line_args()
    logging.basicConfig(level=args.log, format='%(levelname)s: %(message)s')
    try:
        run(args.addr, args.port, args.protocol, args.message, args.timeout, args.transcript, args.serve)
    except (OSError, ValueError, TypeError) as exc:
        logging.error('Alice: %s', exc)
        return 1
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
