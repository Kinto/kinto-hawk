import pkg_resources

#: Module version, as defined in PEP-0396.
__version__ = pkg_resources.get_distribution(__package__).version


def includeme(config):
    config.add_api_capability(
        'hawk',
        version=__version__,
        description='Hawk requests authentication',
        url='https://github.com/Kinto/kinto-hawk')
