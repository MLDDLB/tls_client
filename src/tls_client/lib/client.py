# -*- coding: UTF-8 -*-
import OpenSSL
import random
import socket

import tls_client.lib.session_storage as session_storage
import tls_client.lib.keylogger as keylogger

from contextlib import contextmanager


class TLSClient:
    VERSION_TO_METHOD_MAP = {
        2: OpenSSL.SSL.TLSv1_2_METHOD,
        3: OpenSSL.SSL.TLS_METHOD,
    }

    CACHE_MODE_MAP = {
        "no_cache": OpenSSL.SSL.SESS_CACHE_OFF,
        "client": OpenSSL.SSL.SESS_CACHE_CLIENT,
        "server": OpenSSL.SSL.SESS_CACHE_SERVER,
        "both": OpenSSL.SSL.SESS_CACHE_BOTH,
    }

    def __init__(
        self,
        ciphers=[],
        elyptic_curves=[],
        root_certificate_filepath=None,
        client_certificate_filepath=None,
        session_caching_policy="no_cache",
        keylog_filepath=None,
        keylog_to_stderr=False,
        strict_verify_certificate=True,
        default_timeout=300,
    ):
        self.ciphers = set(ciphers)
        self.elyptic_curves = set(elyptic_curves)
        self.root_certificate_filepath = root_certificate_filepath
        self.strict_verify_certificate = strict_verify_certificate
        self.client_certificate_filepath = client_certificate_filepath
        self.default_timeout=default_timeout

        self._session_storage = session_storage.SessionStorage(cache_mode=self.CACHE_MODE_MAP[session_caching_policy])
        self._keylogger = keylogger.KeyLogger(keylog_filepath, log_to_stderr=keylog_to_stderr)
        self._connection: OpenSSL.SSL.Connection = None

    @property
    def available_versions(self):
        return list(self.VERSION_TO_METHOD_MAP.keys())

    @property
    def session_caching_policies(self):
        return list(self.CACHE_MODE_MAP.keys())

    def init_from_config(self, config):
        self.root_certificate_filepath = config.get("certpath", None)
        self.client_certificate_filepath = config["client_certificate_path"]
        
        session_caching_policy = config.get("session_caching_policy", None)
        if session_caching_policy is not None:
            try:
                self._session_storage = session_storage.SessionStorage(cache_mode=self.CACHE_MODE_MAP[session_caching_policy])
            except KeyError:
                raise ValueError(f"Session policy must be in {self.session_caching_policies}")
        
        keylog_settings = config.get("log_keys", None)
        if keylog_settings and "filepath" in keylog_settings:
            self._keylogger = keylogger.KeyLogger(keylog_settings["filepath"])
        elif keylog_settings and "log_to_stderr" in keylog_settings:
            self._keylogger = keylogger.KeyLogger(log_to_stderr=True)

        self.strict_verify_certificate = config.get("strict_verify_certificate", False)
        self.default_timeout = config.get("timeout", 300)
        
        ciphersuites = config.get("ciphersuites")
        if ciphersuites:
            self.ciphers = set(map(lambda x: x.encode(), ciphersuites))
            
        elyptic_curves = config.get("elyptic_curves")
        if elyptic_curves:
            self.elyptic_curves = set(elyptic_curves)
            
    def make_context(
        self,
        timeout=None,
        version=2,
        ciphers=None,
        elyptic_curve=None,
        use_client_certificate=True,
    ):
        method = self.VERSION_TO_METHOD_MAP.get(version, None)
        if method is None:
            raise ValueError(
                f"Version has to be in {self.available_versions}; Other versions are not supported"
            )

        context = OpenSSL.SSL.Context(method)

        if ciphers and not (set(ciphers) - self.ciphers):
            context.set_cipher_list(ciphers)
        elif not ciphers:
            context.set_cipher_list(b":".join(list(self.ciphers)))
        else:
            raise ValueError(
                "Some of the ciphers provided aren't supported by the client"
            )

        context.set_session_cache_mode(self._session_storage.cache_mode)

        if timeout:
            context.set_timeout(timeout)
        else:
            context.set_timeout(self.default_timeout)

        if self.strict_verify_certificate:
            context.set_verify(OpenSSL.SSL.VERIFY_PEER)
        else:
            context.set_verify(OpenSSL.SSL.VERIFY_NONE)

        # session tickets aren't supported
        context.set_options(OpenSSL.SSL.OP_NO_TICKET)

        if elyptic_curve and elyptic_curve in self.elyptic_curves:
            context.set_tmp_ecdh(OpenSSL.crypto.get_elliptic_curve(elyptic_curve))
        elif elyptic_curve:
            raise ValueError("Selected elyptic curve isn't available for use in this client instance")
        else:
            context.set_tmp_ecdh(OpenSSL.crypto.get_elliptic_curve(random.choice(list(self.elyptic_curves))))

        if self.root_certificate_filepath:
            context.load_verify_locations(self.root_certificate_filepath)
        else:
            context.set_default_verify_paths()

        if use_client_certificate and self.client_certificate_filepath:
            context.use_certificate_file(self.client_certificate_path)

        context.set_keylog_callback(self._keylogger.write)

        return context 

    @contextmanager
    def connect(
        self,
        host,
        port,
        timeout=None,
        version=2,
        ciphers=None,
        elyptic_curve=None,
        use_client_certificate=True,
        reuse_session=True,
    ):
        try:
            with self._keylogger.start_logging():
                context = self.make_context(
                    timeout=timeout,
                    version=version,
                    ciphers=ciphers,
                    elyptic_curve=elyptic_curve,
                    use_client_certificate=use_client_certificate,
                )

                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.bind(("", 0))

                self._connection = OpenSSL.SSL.Connection(context, sock)
                
                session = self._session_storage.get_session(host)
                if session and reuse_session:
                    self._connection.set_session(session)
                
                self._connection.connect((host, port))

                yield
        finally:
            self._session_storage.cache_session(host, self._connection.get_session())
            is_down = self._connection.shutdown()
            if not is_down:
                while self._connection.get_shutdown() != OpenSSL.SSL.SENT_SHUTDOWN | OpenSSL.SSL.RECEIVED_SHUTDOWN:
                    self.recv()

    def send(self, msg):
        self._connection.sendall(msg)

    def recv(self):
        response = [""]
        try:
            response.append(self._connection.read(1500).decode())
        except OpenSSL.SSL.ZeroReturnError:
            pass
        except UnicodeDecodeError:
            pass
        return "".join(response)
