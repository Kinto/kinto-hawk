import mock
import unittest

from kinto.core.testing import get_user_headers
from kinto.plugins.accounts.scripts import create_user

from requests_hawk import HawkAuth

from . import BaseWebTest


class HawkSessionViewTest(BaseWebTest, unittest.TestCase):

    def setUp(self):
        # Create alice user
        create_user({"registry": self.app.app.registry}, "alice", "123456")

    def test_hawk_session_endpoint_can_be_authenticated_via_basic_auth(self):
        resp = self.app.post('/hawk-sessions', headers=get_user_headers('alice', '123456'))
        assert 'Hawk-Session-Token' in resp.headers

    def test_hawk_session_endpoint_can_fail_with_wrong_basic_auth(self):
        resp = self.app.post('/hawk-sessions',
                             headers=get_user_headers('alice', 'wrong'),
                             status=401)
        assert 'WWW-Authenticate' in resp.headers
        assert resp.headers['WWW-Authenticate'] == 'Basic realm="Realm"'


class HawkSessionTest(BaseWebTest, unittest.TestCase):

    def setUp(self):
        # Create alice user
        create_user({"registry": self.app.app.registry}, "alice", "123456")
        # Create hawk session
        resp = self.app.post('/hawk-sessions', headers=get_user_headers('alice', '123456'))
        hawk_session = resp.headers['Hawk-Session-Token']
        self.auth = HawkAuth(hawk_session=hawk_session)

    def test_user_id_is_correct(self):
        request = mock.MagicMock(headers={},
                                 host='localhost',
                                 url='http://localhost/v1/',
                                 method='GET', body='', content_type='')
        self.auth(request)
        resp = self.app.get('/', headers=request.headers)
        assert 'user' in resp.json
        assert resp.json['user']['id'] == 'account:alice'
        assert 'Server-Authorization' in resp.headers

    def test_nonce_reuse_fails(self):
        request = mock.MagicMock(headers={},
                                 host='localhost',
                                 url='http://localhost/v1/buckets',
                                 method='GET', body='', content_type='')
        self.auth(request)
        self.app.get('/buckets', headers=request.headers)
        self.app.get('/buckets', headers=request.headers, status=401)

    def test_if_authentication_missing_returns_www_authenticate_header(self):
        resp = self.app.get('/buckets', status=401)
        assert 'WWW-Authenticate' in resp.headers
        assert resp.headers['WWW-Authenticate'] == 'Hawk realm="Realm"'

    def test_if_authentication_is_wrong_return_401(self):
        request = mock.MagicMock(headers={},
                                 host='localhost',
                                 url='http://localhost/v1/',
                                 method='GET', body='', content_type='')
        self.auth(request)
        self.app.get('/buckets', headers=request.headers, status=401)

    def test_broken_header(self):
        self.app.get('/buckets', headers={"Authorization": "Hawk"}, status=401)

    def test_wrong_authmeth(self):
        self.app.get('/buckets', headers={"Authorization": "Hwak mac"}, status=401)

    def test_unknown_hawk_session(self):
        auth = HawkAuth(id="foo", key="bar")
        request = mock.MagicMock(headers={},
                                 host='localhost',
                                 url='http://localhost/v1/buckets',
                                 method='GET', body='', content_type='')
        auth(request)
        self.app.get('/buckets', headers=request.headers, status=401)

    def test_hawk_header_expired(self):
        auth = HawkAuth(_timestamp=1424738100, **self.auth.credentials)
        request = mock.MagicMock(headers={},
                                 host='localhost',
                                 url='http://localhost/v1/buckets',
                                 method='GET', body='', content_type='')
        auth(request)
        resp = self.app.get('/buckets', headers=request.headers, status=401)
        assert 'WWW-Authenticate' in resp.headers
