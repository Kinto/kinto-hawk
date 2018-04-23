import codecs
import os

from kinto.core import Service, utils
from kinto.core.authorization import PRIVATE
from pyramid import httpexceptions
from pyramid.response import Response
from requests_hawk import HawkAuth

from . import HAWK_SESSION_KEY


sessions = Service(name='hawk-sessions',
                   path='/hawk-sessions',
                   cors_headers=('Hawk-Session-Token',))


@sessions.post(permission=PRIVATE)
def hawk_sessions(request):
    """Helper to give Firefox Account configuration information."""
    if request.prefixed_userid.startswith('account:'):
        settings = request.registry.settings
        hmac_secret = settings['userid_hmac_secret']
        algorithm = settings.get('hawk.algorithm', 'sha256')

        token = os.urandom(32).hex()

        hawk_auth = HawkAuth(hawk_session=token, algorithm=algorithm)
        credentials = hawk_auth.credentials

        encoded_id = utils.hmac_digest(hmac_secret, credentials['id'].decode('utf-8'))
        cache_key = HAWK_SESSION_KEY.format(encoded_id)
        cache_ttl = int(settings.get('account_cache_ttl_seconds', 30))

        session = utils.json.dumps({
            "key": credentials["key"],
            "algorithm": credentials["algorithm"],
            "user_id": request.authenticated_userid
        })
        request.registry.cache.set(cache_key, session, cache_ttl)
        headers = {'Hawk-Session-Token': token}
        return Response(headers=headers, status_code=201)

    raise httpexceptions.HTTPForbidden()
