import importlib
import os
from vulnman.conf import default_settings


class Settings(object):
    def __init__(self):
        settings_module = os.environ.get("VULNMAN_SETTINGS_MODULE")
        for setting in dir(default_settings):
            if setting.isupper():
                setattr(self, setting, getattr(default_settings, setting))
        if settings_module:
            mod = importlib.import_module(settings_module)
            for setting in dir(mod):
                if setting.isupper():
                    setting_value = getattr(mod, setting)
                    setattr(self, setting, setting_value)

    def overwrite(self, key, value):
        setattr(self, key, value)


settings = Settings()
