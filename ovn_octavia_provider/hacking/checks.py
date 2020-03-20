# Copyright (c) 2014 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import re


def flake8ext(f):
    """Decorator to indicate flake8 extension.

    This is borrowed from hacking.core.flake8ext(), but at now it is used
    only for unit tests to know which are ovn_octavia_provider flake8
    extensions.
    """
    f.name = __name__
    return f


# Guidelines for writing new hacking checks
#
#  - Use only for OVN Octavia provider specific tests. OpenStack
#    general tests should be submitted to the common 'hacking' module.
#  - Pick numbers in the range N3xx. Find the current test with
#    the highest allocated number and then pick the next value.
#  - Keep the test method code in the source file ordered based
#    on the N3xx value.
#  - List the new rule in the top level HACKING.rst file
#  - Add test cases for each new rule to
#    ovn_octavia_provider/tests/unit/hacking/test_checks.py


unittest_imports_dot = re.compile(r"\bimport[\s]+unittest\b")
unittest_imports_from = re.compile(r"\bfrom[\s]+unittest\b")
filter_match = re.compile(r".*filter\(lambda ")

tests_imports_dot = re.compile(r"\bimport[\s]+ovn_octavia_provider.tests\b")
tests_imports_from1 = re.compile(r"\bfrom[\s]+ovn_octavia_provider.tests\b")
tests_imports_from2 = re.compile(
    r"\bfrom[\s]+ovn_octavia_provider[\s]+import[\s]+tests\b")
no_line_continuation_backslash_re = re.compile(r'.*(\\)\n')


@flake8ext
def check_assert_called_once_with(logical_line, filename):
    """Try to detect unintended calls of nonexistent mock methods like:

                 assert_called_once
                 assertCalledOnceWith
                 assert_has_called
                 called_once_with

    N322
    """

    if 'ovn_octavia_provider/tests/' in filename:
        if '.assert_called_once_with(' in logical_line:
            return
        uncased_line = logical_line.lower().replace('_', '')

        check_calls = ['.assertcalledonce', '.calledoncewith']
        if any(x for x in check_calls if x in uncased_line):
            msg = ("N322: Possible use of no-op mock method. "
                   "please use assert_called_once_with.")
            yield (0, msg)

        if '.asserthascalled' in uncased_line:
            msg = ("N322: Possible use of no-op mock method. "
                   "please use assert_has_calls.")
            yield (0, msg)


@flake8ext
def check_asserttruefalse(logical_line, filename):
    """N328 - Don't use assertEqual(True/False, observed)."""

    if 'ovn_octavia_provider/tests/' in filename:
        if re.search(r"assertEqual\(\s*True,[^,]*(,[^,]*)?", logical_line):
            msg = ("N328: Use assertTrue(observed) instead of "
                   "assertEqual(True, observed)")
            yield (0, msg)
        if re.search(r"assertEqual\([^,]*,\s*True(,[^,]*)?", logical_line):
            msg = ("N328: Use assertTrue(observed) instead of "
                   "assertEqual(True, observed)")
            yield (0, msg)
        if re.search(r"assertEqual\(\s*False,[^,]*(,[^,]*)?", logical_line):
            msg = ("N328: Use assertFalse(observed) instead of "
                   "assertEqual(False, observed)")
            yield (0, msg)
        if re.search(r"assertEqual\([^,]*,\s*False(,[^,]*)?", logical_line):
            msg = ("N328: Use assertFalse(observed) instead of "
                   "assertEqual(False, observed)")
            yield (0, msg)


@flake8ext
def check_assertempty(logical_line, filename):
    """Enforce using assertEqual parameter ordering in case of empty objects.

    N330
    """

    if 'ovn_octavia_provider/tests/' in filename:
        msg = ("N330: Use assertEqual(*empty*, observed) instead of "
               "assertEqual(observed, *empty*). *empty* contains "
               "{}, [], (), set(), '', \"\"")
        empties = r"(\[\s*\]|\{\s*\}|\(\s*\)|set\(\s*\)|'\s*'|\"\s*\")"
        reg = r"assertEqual\(([^,]*,\s*)+?%s\)\s*$" % empties
        if re.search(reg, logical_line):
            yield (0, msg)


@flake8ext
def check_assertisinstance(logical_line, filename):
    """N331 - Enforce using assertIsInstance."""

    if 'ovn_octavia_provider/tests/' in filename:
        if re.search(r"assertTrue\(\s*isinstance\(\s*[^,]*,\s*[^,]*\)\)",
                     logical_line):
            msg = ("N331: Use assertIsInstance(observed, type) instead "
                   "of assertTrue(isinstance(observed, type))")
            yield (0, msg)


@flake8ext
def check_assertequal_for_httpcode(logical_line, filename):
    """N332 - Enforce correct oredering for httpcode in assertEqual."""

    msg = ("N332: Use assertEqual(expected_http_code, observed_http_code) "
           "instead of assertEqual(observed_http_code, expected_http_code)")
    if 'ovn_octavia_provider/tests/' in filename:
        if re.search(r"assertEqual\(\s*[^,]*,[^,]*HTTP[^\.]*\.code\s*\)",
                     logical_line):
            yield (0, msg)


@flake8ext
def check_no_imports_from_tests(logical_line, filename):
    """N343 - Production code must not import from ovn_octavia_provider.tests.*

    """

    msg = ("N343 Production code must not import from "
           "ovn_octavia_provider.tests.*")

    if 'ovn_octavia_provider/tests/' in filename:
        return

    for regex in tests_imports_dot, tests_imports_from1, tests_imports_from2:
        if re.match(regex, logical_line):
            yield(0, msg)


@flake8ext
def check_python3_no_filter(logical_line):
    """N344 - Use list comprehension instead of filter(lambda)."""

    msg = ("N344: Use list comprehension instead of "
           "filter(lambda obj: test(obj), data) on python3.")

    if filter_match.match(logical_line):
        yield(0, msg)


def check_line_continuation_no_backslash(logical_line, tokens):
    """N346 - Don't use backslashes for line continuation.

    :param logical_line: The logical line to check. Not actually used.
    :param tokens: List of tokens to check.
    :returns: None if the tokens don't contain any issues, otherwise a tuple
              is yielded that contains the offending index in the logical
              line and a message describe the check validation failure.
    """
    backslash = None
    for token_type, text, start, end, orig_line in tokens:
        m = no_line_continuation_backslash_re.match(orig_line)
        if m:
            backslash = (start[0], m.start(1))
            break

    if backslash is not None:
        msg = 'N346: Backslash line continuations not allowed'
        yield backslash, msg


def factory(register):
    register(check_assert_called_once_with)
    register(check_asserttruefalse)
    register(check_assertempty)
    register(check_assertisinstance)
    register(check_assertequal_for_httpcode)
    register(check_no_imports_from_tests)
    register(check_python3_no_filter)
    register(check_line_continuation_no_backslash)
