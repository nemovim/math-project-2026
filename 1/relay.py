"""Transparent byte relay and live observation for the course's tiny RSA/DH.
Only wire JSON is observed. Private process state is never accessed.
An analysis failure disables that observer, not forwarding of the traffic.
"""
import json
import logging
from pathlib import Path
import socket
import threading
from crypto_math import (decrypt_message, dh_aes_key, dh_parameter_error,
                         dh_shared, mod_inverse, rsa_decrypt_key, validate_rsa_public)
from eve import discrete_log, factor_modulus
from wire import MAX_JSON_BYTES


class JsonObserverBuffer:
    def __init__(self):
        self.buffer = b''
        self.decoder = json.JSONDecoder()

    def feed(self, chunk):
        self.buffer += chunk
        if len(self.buffer) > MAX_JSON_BYTES:
            raise ValueError('observer JSON exceeds the size limit')
        while self.buffer.strip():
            self.buffer = self.buffer.lstrip()
            if not self.buffer.startswith(b'{'):
                raise ValueError('observer expected a JSON object')
            try:
                text = self.buffer.decode('utf-8')
                obj, end = self.decoder.raw_decode(text)
            except (UnicodeDecodeError, json.JSONDecodeError):
                return
            self.buffer = text[end:].encode('utf-8')
            yield obj


class Interceptor:
    def __init__(self, transcript=None):
        self.mode = None
        self.rsa = None
        self.dh = None
        self.key = None
        self.plaintexts = []
        self.errors = []
        self.lock = threading.Lock()
        self.transcript = Path(transcript) if transcript else None
        if self.transcript:
            self.transcript.parent.mkdir(parents=True, exist_ok=True)
            self.transcript.write_text('', encoding='utf-8')

    def observe(self, obj, sender):
        # The handshake is observed before forwarding, so its key is ready
        # before the opposite direction can carry the following AES response.
        with self.lock:
            if self.transcript:
                with self.transcript.open('a', encoding='utf-8') as stream:
                    stream.write(json.dumps(obj, ensure_ascii=True)+'\n')
            op, kind = obj.get('opcode'), obj.get('type')
            if op == 1 and kind == 'RSA':
                n, e = obj['parameter']['n'], obj['public']
                validate_rsa_public(e, n)
                p, q = factor_modulus(n)
                d = mod_inverse(e, (p-1)*(q-1))
                self.mode, self.rsa, self.key = 'RSA', (n, d), None
                print(f'[Eve] RSA: n={n} = {p} * {q}; recovered d={d}', flush=True)
            elif op == 2 and kind == 'RSA':
                if self.rsa is None:
                    raise ValueError('RSA public-key offer was not observed')
                n, d = self.rsa
                self.key = rsa_decrypt_key(obj['encrypted_key'], d, n)
                print(f'[Eve] recovered AES key: {self.key.hex()}', flush=True)
            elif op == 1 and kind == 'DH':
                if 'parameter' in obj:
                    p, g = obj['parameter']['p'], obj['parameter']['g']
                    error = dh_parameter_error(p, g)
                    if error:
                        raise ValueError(error)
                    public = obj['public']
                    dh_shared(public, 1, p)  # range/type validation
                    self.mode, self.dh, self.key = 'DH', (p, g, public), None
                else:
                    if self.dh is None:
                        raise ValueError('DH parameter offer was not observed')
                    p, g, public = self.dh
                    exponent = discrete_log(g, public, p)
                    shared = dh_shared(obj['public'], exponent, p)
                    self.key = dh_aes_key(shared)
                    print(f'[Eve] DH: recovered exponent mod (p-1)={exponent}; secret={shared}', flush=True)
                    print(f'[Eve] recovered AES key: {self.key.hex()}', flush=True)
            elif op == 2 and kind == 'AES':
                if self.key is None:
                    raise ValueError('AES key was not recovered')
                plain = decrypt_message(self.key, obj['encryption'])
                self.plaintexts.append({'sender': sender, 'text': plain})
                print(f'[Eve] intercepted ({sender}): {plain!r}', flush=True)
            elif op == 3:
                print(f"[Eve] observed peer error: {obj.get('error')}", flush=True)


def _pump(source, destination, interceptor, sender):
    parser = JsonObserverBuffer()
    observe = True
    try:
        while True:
            data = source.recv(4096)
            if not data:
                break
            if observe:
                try:
                    for obj in parser.feed(data):
                        interceptor.observe(obj, sender)
                except (ValueError, KeyError, TypeError, OSError) as exc:
                    # Do not let a failed attack change the peers' protocol.
                    observe = False
                    with interceptor.lock:
                        interceptor.errors.append(str(exc))
                    logging.warning('Eve observation disabled for %s: %s', sender, exc)
            destination.sendall(data)  # forward the original bytes, not reserialized JSON
    except OSError as exc:
        logging.debug('Relay %s ended: %s', sender, exc)
    finally:
        try:
            destination.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def relay_connection(alice_socket, bob_addr, bob_port, timeout=30.0, transcript=None):
    with alice_socket:
        alice_socket.settimeout(timeout)
        with socket.create_connection((bob_addr, bob_port), timeout=timeout) as bob_socket:
            bob_socket.settimeout(timeout)
            interceptor = Interceptor(transcript)
            threads = [
                threading.Thread(target=_pump, args=(alice_socket, bob_socket, interceptor, 'Alice'), daemon=True),
                threading.Thread(target=_pump, args=(bob_socket, alice_socket, interceptor, 'Bob'), daemon=True),
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            return interceptor


def run_relay(listen_addr, listen_port, bob_addr, bob_port, timeout=30.0,
              once=False, transcript=None):
    if timeout <= 0:
        raise ValueError('timeout must be positive')
    def handle(conn, path):
        try:
            relay_connection(conn, bob_addr, bob_port, timeout, path)
            return 0
        except (OSError, ValueError) as exc:
            logging.error('Eve relay: %s', exc)
            return 1
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((listen_addr, listen_port))
        listener.listen(10)
        print(f'Eve is listening on {listen_addr}:{listener.getsockname()[1]} -> {bob_addr}:{bob_port}', flush=True)
        count = 0
        while True:
            conn, _ = listener.accept()
            count += 1
            path = transcript
            if path and not once:
                source = Path(path)
                path = source.with_name(f'{source.stem}-{count:03d}{source.suffix}')
            if once:
                return handle(conn, path)
            threading.Thread(target=handle, args=(conn, path), daemon=True).start()
