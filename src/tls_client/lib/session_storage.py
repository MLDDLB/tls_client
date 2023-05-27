# -*- coding: UTF-8 -*-
import OpenSSL


class SessionStorage:
    def __init__(self, cache_mode=OpenSSL.SSL.SESS_CACHE_OFF) -> None:
        self._storage = {}

        self.cache_mode = cache_mode

    def get_session(self, host):
        return self._storage.get(host, None)

    def cache_session(self, host, session):
        if session and self.cache_mode in {
            OpenSSL.SSL.SESS_CACHE_CLIENT,
            OpenSSL.SSL.SESS_CACHE_BOTH,
        }:
            self._storage[host] = session
