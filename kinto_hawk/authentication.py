from functools import partial

from pyramid.interfaces import IAuthenticationPolicy
from pyramid.authentication import CallbackAuthenticationPolicy

from mohawk import Receiver
from mohawk.exc import HawkFail, TokenExpired
from zope.interface import implementer

from kinto.core import utils

from . import HAWK_SESSION_KEY


REIFY_KEY = 'hawk_verified_token'


@implementer(IAuthenticationPolicy)
class HawkAuthenticationPolicy(CallbackAuthenticationPolicy):
    def __init__(self, realm='Realm'):
        self.realm = realm

    def forget(self, request):
        """A no-op. Credentials are sent on every request.
        Return WWW-Authenticate Realm header for Hawk.
        """
        return [('WWW-Authenticate', 'Hawk realm="%s"' % self.realm)]

    def unauthenticated_userid(self, request):
        """Return the Account userid or ``None`` if token could not be verified.
        """
        authorization = request.headers.get('Authorization', '')
        try:
            authmeth, token = authorization.split(' ', 1)
        except ValueError:
            return None
        if authmeth.lower() != 'hawk':
            return None

        user_id = self._verify_credentials(request)

        return user_id

    def lookup_credentials(self, request, sender_id):
        settings = request.registry.settings
        hmac_secret = settings['userid_hmac_secret']
        algorithm = settings.get('hawk.algorithm', 'sha256')

        cache_key = HAWK_SESSION_KEY.format(utils.hmac_digest(hmac_secret, sender_id))
        # Check cache to see if we know this session.
        cache = request.registry.cache
        session = cache.get(cache_key)

        if session:
            try:
                request.bound_data['info'] = utils.json.loads(session)
            except ValueError:
                cache.delete(cache_key)
                raise LookupError('Invalid session data')

            return {'id': sender_id,
                    'key': request.bound_data['info']['key'],
                    'algorithm': algorithm}

        raise LookupError('unknown sender')

    def seen_nonce(self, request, sender_id, nonce, timestamp):
        cache = request.registry.cache
        cache_key = 'hawk:{id}:{nonce}:{ts}'.format(id=sender_id, nonce=nonce, ts=timestamp)
        seen = cache.get(cache_key)
        if seen is None:
            cache.set(cache_key, '', 300)  # XXX: Make this 300 a setting
        return seen is not None

    def _verify_credentials(self, request):
        """Check storage for the request account HAWK credentials.
        """
        if REIFY_KEY not in request.bound_data:
            kwargs = {}
            kwargs['content'] = request.body or ''
            kwargs['content_type'] = request.headers.get('Content-Type', '')

            try:
                request.receiver = Receiver(partial(self.lookup_credentials, request),
                                            request.headers['Authorization'],
                                            request.url,
                                            request.method,
                                            seen_nonce=partial(self.seen_nonce, request),
                                            accept_untrusted_content=True,
                                            **kwargs)
            except HawkFail as e:
                request.bound_data[REIFY_KEY] = None
            except TokenExpired as expiry:
                request.response.headers['WWW-Authenticate'] = expiry.www_authenticate
            else:
                request.bound_data[REIFY_KEY] = request.bound_data['info']['user_id']

        return request.bound_data[REIFY_KEY]
