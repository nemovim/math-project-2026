"""Bob/server: accept the protocol requested by Alice."""
import argparse
import logging
import secrets
import socket
import threading
from pathlib import Path
from crypto_math import (PRIMES, choose_generator, decrypt_message, dh_aes_key, dh_parameter_error,
                         dh_private, dh_shared, encrypt_message, generate_rsa_key,
                         mod_pow, rsa_decrypt_key)
from wire import JsonChannel, PeerError, ProtocolError, expect, parameters, send_error


def session(channel, message, fault=None):
    request = channel.receive()
    # PPT p.17 also mentions a server receiving p/g. Accept that offer
    # without changing the default p.8 request/response sequence.
    if request.get('opcode') == 1 and request.get('type') == 'DH':
        expect(request, 1, 'DH')
        params = parameters(request)
        p, g = params.get('p'), params.get('g')
        error = dh_parameter_error(p, g)
        if error:
            raise ProtocolError(error)
        private = dh_private(p)
        key = dh_aes_key(dh_shared(request.get('public'), private, p))
        channel.send({'opcode': 1, 'type': 'DH', 'public': mod_pow(g, private, p)})
        send_then_receive(channel, key, message, 'DH')
        return
    expect(request, 0)
    protocol = request.get('type')
    if protocol not in ('RSAKey', 'RSA', 'DH'):
        raise ProtocolError('unsupported protocol')
    if protocol in ('RSAKey', 'RSA'):
        rsa = generate_rsa_key()
        if protocol == 'RSAKey':
            # Private parameters appear ONLY in this explicit key-test protocol.
            channel.send({'opcode': 0, 'type': 'RSAKey', 'private': rsa.d,
                          'public': rsa.e, 'parameter': {'p': rsa.p, 'q': rsa.q}})
            print('RSAKey generated and sent', flush=True)
            return
        channel.send({'opcode': 1, 'type': 'RSA', 'public': rsa.e,
                      'parameter': {'n': rsa.n}})
        reply = expect(channel.receive(), 2, 'RSA')
        key = rsa_decrypt_key(reply.get('encrypted_key'), rsa.d, rsa.n)
    else:
        p = secrets.choice(PRIMES)
        g = choose_generator(p)
        private = dh_private(p)
        public = mod_pow(g, private, p)
        # Deliberate bad parameters let the team demonstrate Protocol IV.
        sent_p = 405 if fault == 'prime' else p
        sent_g = 1 if fault == 'generator' else g
        channel.send({'opcode': 1, 'type': 'DH', 'public': public,
                      'parameter': {'p': sent_p, 'g': sent_g}})
        reply = expect(channel.receive(), 1, 'DH')
        if fault:
            raise ProtocolError('peer accepted deliberately invalid DH parameters')
        key = dh_aes_key(dh_shared(reply.get('public'), private, p))

    send_then_receive(channel, key, message, protocol)


def send_then_receive(channel, key, message, protocol):
    channel.send({'opcode': 2, 'type': 'AES',
                  'encryption': encrypt_message(key, message)})
    reply = expect(channel.receive(), 2, 'AES')
    plain = decrypt_message(key, reply.get('encryption'))
    print(f'Alice -> Bob (decrypted): {plain}', flush=True)
    print(f'{protocol} exchange: PASS', flush=True)


def handler(sock, message='Hello from Bob', timeout=30.0, transcript=None, fault=None):
    with sock:
        sock.settimeout(timeout)
        channel = JsonChannel(sock, transcript)
        try:
            session(channel, message, fault)
            return True
        except PeerError as exc:
            print(f'Peer error: {exc}', flush=True)
        except (ValueError, KeyError, TypeError) as exc:
            logging.error('Bob: %s', exc)
            send_error(channel, str(exc))
        except OSError as exc:
            logging.error('Bob connection: %s', exc)
    return False


def run(addr, port, message='Hello from Bob', timeout=30.0, once=False,
        transcript=None, fault=None):
    if timeout <= 0:
        raise ValueError('timeout must be positive')
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as bob:
        bob.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        bob.bind((addr, port))
        bob.listen(10)
        print(f'Bob is listening on {addr}:{bob.getsockname()[1]}', flush=True)
        count = 0
        while True:
            conn, info = bob.accept()
            count += 1
            logging.info('Bob accepts %s:%s', *info)
            path = transcript
            if transcript and not once:
                source = Path(transcript)
                path = source.with_name(f'{source.stem}-{count:03d}{source.suffix}')
            args = (conn, message, timeout, path, fault)
            if once:
                return 0 if handler(*args) else 1
            threading.Thread(target=handler, args=args, daemon=True).start()


def command_line_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-a', '--addr', default='0.0.0.0')
    parser.add_argument('-p', '--port', required=True, type=int)
    parser.add_argument('-m', '--message', default='Hello from Bob')
    parser.add_argument('-l', '--log', default='INFO',
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'])
    parser.add_argument('--timeout', type=float, default=30.0)
    parser.add_argument('--once', action='store_true', help='Handle one connection and exit')
    parser.add_argument('--transcript', help='Save JSON traffic; server adds a session number')
    faults = parser.add_mutually_exclusive_group()
    faults.add_argument('--fault', choices=['prime', 'generator'],
                        help='Intentionally send bad DH parameters for Protocol IV')
    faults.add_argument('--wrong-prime', dest='fault', action='store_const', const='prime')
    faults.add_argument('--wrong-generator', dest='fault', action='store_const', const='generator')
    return parser.parse_args()


def main():
    args = command_line_args()
    logging.basicConfig(level=args.log, format='%(levelname)s: %(message)s')
    try:
        return run(args.addr, args.port, args.message, args.timeout,
                   args.once, args.transcript, args.fault)
    except (OSError, ValueError) as exc:
        logging.error('Bob: %s', exc)
        return 1
    except KeyboardInterrupt:
        print('\nBob stopped.', flush=True)
        return 0


if __name__ == '__main__':
    raise SystemExit(main())
