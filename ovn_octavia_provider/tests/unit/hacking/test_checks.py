#    Copyright 2015
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import testtools

from oslotest import base

from ovn_octavia_provider.hacking import checks


class HackingTestCase(base.BaseTestCase):
    """Hacking test class.

    This class tests the hacking checks in ovn_octavia_provider.hacking.checks
    by passing strings to the check methods like the pep8/flake8 parser would.
    The parser loops over each line in the file and then passes the parameters
    to the check method. The parameter names in the check method dictate what
    type of object is passed to the check method. The parameter types are::

        logical_line: A processed line with the following modifications:
            - Multi-line statements converted to a single line.
            - Stripped left and right.
            - Contents of strings replaced with "xxx" of same length.
            - Comments removed.
        physical_line: Raw line of text from the input file.
        lines: a list of the raw lines from the input file
        tokens: the tokens that contribute to this logical line
        line_number: line number in the input file
        total_lines: number of lines in the input file
        blank_lines: blank lines before this one
        indent_char: indentation character in this file (" " or "\t")
        indent_level: indentation (with tabs expanded to multiples of 8)
        previous_indent_level: indentation on previous line
        previous_logical: previous logical line
        filename: Path of the file being run through pep8

    When running a test on a check method the return will be False/None if
    there is no violation in the sample input. If there is an error a tuple is
    returned with a position in the line, and a message. So to check the result
    just assertTrue if the check is expected to fail and assertFalse if it
    should pass.
    """

    def assertLinePasses(self, func, *args):
        with testtools.ExpectedException(StopIteration):
            next(func(*args))

    def assertLineFails(self, func, *args):
        self.assertIsInstance(next(func(*args)), tuple)

    def test_assert_called_once_with(self):
        fail_code1 = """
               mock = Mock()
               mock.method(1, 2, 3, test='wow')
               mock.method.assertCalledOnceWith()
               """
        fail_code2 = """
               mock = Mock()
               mock.method(1, 2, 3, test='wow')
               mock.method.called_once_with()
               """
        fail_code3 = """
               mock = Mock()
               mock.method(1, 2, 3, test='wow')
               mock.method.assert_has_called()
               """
        pass_code = """
               mock = Mock()
               mock.method(1, 2, 3, test='wow')
               mock.method.assert_called_once_with()
               """
        pass_code2 = """
               mock = Mock()
               mock.method(1, 2, 3, test='wow')
               mock.method.assert_has_calls()
               """
        self.assertEqual(
            1, len(list(checks.check_assert_called_once_with(fail_code1,
                        "ovn_octavia_provider/tests/test_assert.py"))))
        self.assertEqual(
            1, len(list(checks.check_assert_called_once_with(fail_code2,
                        "ovn_octavia_provider/tests/test_assert.py"))))
        self.assertEqual(
            0, len(list(checks.check_assert_called_once_with(pass_code,
                        "ovn_octavia_provider/tests/test_assert.py"))))
        self.assertEqual(
            1, len(list(checks.check_assert_called_once_with(fail_code3,
                        "ovn_octavia_provider/tests/test_assert.py"))))
        self.assertEqual(
            0, len(list(checks.check_assert_called_once_with(pass_code2,
                        "ovn_octavia_provider/tests/test_assert.py"))))

    def test_asserttruefalse(self):
        true_fail_code1 = """
               test_bool = True
               self.assertEqual(True, test_bool)
               """
        true_fail_code2 = """
               test_bool = True
               self.assertEqual(test_bool, True)
               """
        true_pass_code = """
               test_bool = True
               self.assertTrue(test_bool)
               """
        false_fail_code1 = """
               test_bool = False
               self.assertEqual(False, test_bool)
               """
        false_fail_code2 = """
               test_bool = False
               self.assertEqual(test_bool, False)
               """
        false_pass_code = """
               test_bool = False
               self.assertFalse(test_bool)
               """
        self.assertEqual(
            1, len(list(checks.check_asserttruefalse(true_fail_code1,
                        "ovn_octavia_provider/tests/test_assert.py"))))
        self.assertEqual(
            1, len(list(checks.check_asserttruefalse(true_fail_code2,
                        "ovn_octavia_provider/tests/test_assert.py"))))
        self.assertEqual(
            0, len(list(checks.check_asserttruefalse(true_pass_code,
                        "ovn_octavia_provider/tests/test_assert.py"))))
        self.assertEqual(
            1, len(list(checks.check_asserttruefalse(false_fail_code1,
                        "ovn_octavia_provider/tests/test_assert.py"))))
        self.assertEqual(
            1, len(list(checks.check_asserttruefalse(false_fail_code2,
                        "ovn_octavia_provider/tests/test_assert.py"))))
        self.assertFalse(
            list(checks.check_asserttruefalse(false_pass_code,
                 "ovn_octavia_provider/tests/test_assert.py")))

    def test_assertempty(self):
        fail_code = """
                test_empty = %s
                self.assertEqual(test_empty, %s)
                """
        pass_code1 = """
                test_empty = %s
                self.assertEqual(%s, test_empty)
                """
        pass_code2 = """
                self.assertEqual(123, foo(abc, %s))
                """
        empty_cases = ['{}', '[]', '""', "''", '()', 'set()']
        for ec in empty_cases:
            self.assertEqual(
                1, len(list(checks.check_assertempty(fail_code % (ec, ec),
                            "ovn_octavia_provider/tests/test_assert.py"))))
            self.assertEqual(
                0, len(list(checks.check_asserttruefalse(pass_code1 % (ec, ec),
                            "ovn_octavia_provider/tests/test_assert.py"))))
            self.assertEqual(
                0, len(list(checks.check_asserttruefalse(pass_code2 % ec,
                            "ovn_octavia_provider/tests/test_assert.py"))))

    def test_assertisinstance(self):
        fail_code = """
               self.assertTrue(isinstance(observed, ANY_TYPE))
               """
        pass_code1 = """
               self.assertEqual(ANY_TYPE, type(observed))
               """
        pass_code2 = """
               self.assertIsInstance(observed, ANY_TYPE)
               """
        self.assertEqual(
            1, len(list(checks.check_assertisinstance(fail_code,
                        "ovn_octavia_provider/tests/test_assert.py"))))
        self.assertEqual(
            0, len(list(checks.check_assertisinstance(pass_code1,
                        "ovn_octavia_provider/tests/test_assert.py"))))
        self.assertEqual(
            0, len(list(checks.check_assertisinstance(pass_code2,
                        "ovn_octavia_provider/tests/test_assert.py"))))

    def test_assertequal_for_httpcode(self):
        fail_code = """
                self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
                """
        pass_code = """
                self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)
                """
        self.assertEqual(
            1, len(list(checks.check_assertequal_for_httpcode(fail_code,
                        "ovn_octavia_provider/tests/test_assert.py"))))
        self.assertEqual(
            0, len(list(checks.check_assertequal_for_httpcode(pass_code,
                        "ovn_octavia_provider/tests/test_assert.py"))))

    def test_check_no_imports_from_tests(self):
        fail_codes = ('from ovn_octavia_provider import tests',
                      'from ovn_octavia_provider.tests import base',
                      'import ovn_octavia_provider.tests.base')
        for fail_code in fail_codes:
            self.assertEqual(
                1, len(list(checks.check_no_imports_from_tests(fail_code,
                            "ovn_octavia_provider/common/utils.py"))))
            self.assertEqual(
                0, len(list(checks.check_no_imports_from_tests(fail_code,
                            "ovn_octavia_provider/tests/test_fake.py"))))

    def test_check_python3_filter(self):
        f = checks.check_python3_no_filter
        self.assertLineFails(f, "filter(lambda obj: test(obj), data)")
        self.assertLinePasses(f, "[obj for obj in data if test(obj)]")
        self.assertLinePasses(f, "filter(function, range(0,10))")
        self.assertLinePasses(f, "lambda x, y: x+y")

    def test_line_continuation_no_backslash(self):
        results = list(checks.check_line_continuation_no_backslash(
            '', [(1, 'import', (2, 0), (2, 6), 'import \\\n'),
                 (1, 'os', (3, 4), (3, 6), '    os\n')]))
        self.assertEqual(1, len(results))
        self.assertEqual((2, 7), results[0][0])

    def _get_factory_checks(self, factory):
        check_fns = []

        def _reg(check_fn):
            self.assertTrue(hasattr(check_fn, '__call__'))
            self.assertFalse(check_fn in check_fns)
            check_fns.append(check_fn)

        factory(_reg)
        return check_fns

    def test_factory(self):
        self.assertGreater(len(self._get_factory_checks(checks.factory)), 0)
