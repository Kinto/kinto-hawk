import pkg_resources

#: Module version, as defined in PEP-0396.
__version__ = pkg_resources.get_distribution(__package__).version


HAWK_SESSION_KEY = 'hawk:{}'

DEFAULT_SETTINGS = {
    'hawk.algorithm': 'sha256',
    'hawk.nonce_ttl_seconds': 60,
    'hawk.session_ttl_seconds': 5184000  # About 2 months life idle
}


def includeme(config):
    config.add_api_capability(
        'hawk',
        version=__version__,
        description='Hawk requests authentication',
        url='https://github.com/Kinto/kinto-hawk')

    settings = config.get_settings()
    defaults = {k: v for k, v in DEFAULT_SETTINGS.items() if k not in settings}
    config.add_settings(defaults)

    # Sign server responses
    config.add_tween('kinto_hawk.tweens.sign_responses')

    # Activate /hawk-sessions endpoint.
    config.scan('kinto_hawk.views')
