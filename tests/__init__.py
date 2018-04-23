import os
import configparser

from kinto import main as kinto_main
from kinto.core.testing import BaseWebTest as CoreWebTest


here = os.path.abspath(os.path.dirname(__file__))


class BaseWebTest(CoreWebTest):
    api_prefix = "v1"
    entry_point = kinto_main
    config = 'config.ini'

    @classmethod
    def get_app_settings(cls, extras=None):
        ini_path = os.path.join(here, cls.config)
        config = configparser.ConfigParser()
        config.read(ini_path)
        settings = dict(config.items('app:main'))
        if extras:
            settings.update(extras)
        return settings
