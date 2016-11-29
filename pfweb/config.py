import ConfigParser
import os
import hashlib, binascii

class Config():
    def __init__(self):
        self.username = None
        self.password = None

    def _read_file(self):
        """Read configuration file from one of multiple locations"""
        _config_parse = ConfigParser.ConfigParser()
        _configset = _config_parse.read([
            os.path.expanduser('~') + "/.pfweb.ini", 
            '/etc/pfweb.ini',
            '/usr/local/etc/pfweb.ini'])
        
        if len(_configset) < 1:
            raise ValueError("Cannot read any pfweb.ini file")

        self.config_file = _configset[0]

        return _config_parse

    def get_settings(self):
        """Store config settings into the class"""
        _config_parse = self._read_file()

        _required = { 'main': ['secret_key', 'salt', 'username', 'password'] }
        _optional = { 'global': ['state_policy'] }

        for section, params in _required.iteritems():
            for param in params:
                setattr(self, param, _config_parse.get(section, param))

        for section, params in _optional.iteritems():
            try:
                for param in params:
                    setattr(self, param, _config_parse.get(section, param))
            except (ConfigParser.NoOptionError, ConfigParser.NoSectionError):
                pass

    def create_user(self, username, password):
        """Create and store an initial user"""
        _config_parse = self._read_file()

        hashed = self.hash_password(password, _config_parse.get('main', 'salt'))
        
        _config_parse.set('main', 'username', username)
        _config_parse.set('main', 'password', hashed)

        self.username = username
        self.password = hashed

        with open(self.config_file, 'wb') as configfile:
            _config_parse.write(configfile)

    def hash_password(self, password, salt=None):
        """Return a hash of the given password/string"""

        if salt == None:
            salt = self.salt

        # Use PKCS#5 and sha256 to hash the password
        dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        # Return the ascii hex value of the hash
        return binascii.hexlify(dk)