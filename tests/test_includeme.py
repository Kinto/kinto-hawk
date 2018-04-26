import unittest

from kinto_hawk import __version__ as hawk_version

from . import BaseWebTest


class CapabilityTestView(BaseWebTest, unittest.TestCase):

    def test_hawk_capability(self, additional_settings=None):
        resp = self.app.get('/')
        capabilities = resp.json['capabilities']
        assert 'hawk' in capabilities
        expected = {
            "version": hawk_version,
            "url": "https://github.com/Kinto/kinto-hawk",
            "description": "Hawk requests authentication"
        }
        self.assertEqual(expected, capabilities['hawk'])
