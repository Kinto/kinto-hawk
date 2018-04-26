import os

from kinto.core import Service, utils
from pyramid import httpexceptions
from pyramid.response import Response
from pyramid.security import NO_PERMISSION_REQUIRED
from requests_hawk import HawkAuth

from kinto.plugins.accounts.authentication import AccountsAuthenticationPolicy
from . import HAWK_SESSION_KEY


sessions = Service(name='hawk-sessions',
                   path='/hawk-sessions',
                   cors_headers=('Hawk-Session-Token',))


@sessions.post(permission=NO_PERMISSION_REQUIRED)
def hawk_sessions(request):
    """Grab the Hawk Session from another Authentication backend."""

    authn = AccountsAuthenticationPolicy()

    user = authn.authenticated_userid(request)

    if user is None:
        response = httpexceptions.HTTPUnauthorized()
        response.headers.update(authn.forget(request))
        return response

    settings = request.registry.settings
    hmac_secret = settings['userid_hmac_secret']
    algorithm = settings['hawk.algorithm']

    token = os.urandom(32).hex()

    hawk_auth = HawkAuth(hawk_session=token, algorithm=algorithm)
    credentials = hawk_auth.credentials

    encoded_id = utils.hmac_digest(hmac_secret, credentials['id'].decode('utf-8'))
    cache_key = HAWK_SESSION_KEY.format(encoded_id)
    cache_ttl = int(settings['hawk.session_ttl_seconds'])

    session = utils.json.dumps({
        "key": credentials["key"],
        "algorithm": credentials["algorithm"],
        "user_id": user
    })
    request.registry.cache.set(cache_key, session, cache_ttl)
    headers = {'Hawk-Session-Token': token}
    return Response(headers=headers, status_code=201)
