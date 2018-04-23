import pkg_resources

#: Module version, as defined in PEP-0396.
__version__ = pkg_resources.get_distribution(__package__).version


HAWK_SESSION_KEY = 'hawk:{}'


def includeme(config):
    config.add_api_capability(
        'hawk',
        version=__version__,
        description='Hawk requests authentication',
        url='https://github.com/Kinto/kinto-hawk')

    # Sign server responses
    config.add_tween('kinto_hawk.tweens.sign_responses')

    # Activate /hawk-sessions endpoint.
    config.scan('kinto_hawk.views')
