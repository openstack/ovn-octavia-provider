ovn-octavia-provider Style Commandments
===============================================

Read the OpenStack Style Commandments https://docs.openstack.org/hacking/latest/

Below you can find a list of checks specific to this repository.

- [N322] Detect common errors with assert_called_once_with
- [N328] Detect wrong usage with assertEqual
- [N330] Use assertEqual(*empty*, observed) instead of
         assertEqual(observed, *empty*)
- [N331] Detect wrong usage with assertTrue(isinstance()).
- [N332] Use assertEqual(expected_http_code, observed_http_code) instead of
         assertEqual(observed_http_code, expected_http_code).
- [N343] Production code must not import from ovn_octavia_provider.tests.*
- [N344] Python 3: Do not use filter(lambda obj: test(obj), data). Replace it
         with [obj for obj in data if test(obj)].
- [N347] Test code must not import mock library
- [N348] Detect usage of assertItemsEqual
