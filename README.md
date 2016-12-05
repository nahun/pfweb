# pfweb

pfweb is a python web application to manage the OpenBSD Packet Filter (PF). It 
uses *py-pf* to interface with PF and Flask for the web framework. The look 
and feel is based on pfSense and a lot of the ideas are ripped off from them.

## Warning!
There are a lot of people that would say running a web interface for PF is a 
bad idea. There are many reasons why, but here are a couple good ones:

- **Security**: Running pfweb requires the user running the application to have
write access to */dev/pf* to make changes. This gives access to the kernel.
- **Features**: When using a web application to manage PF instead of 
just modifying *pf.conf*, you lose massive amounts of powerful features and 
flexibility.

So why would use you use pfweb? Maybe a home network or an already secured lab.
I don't judge though, use it how you want. I've had fun making it as well.

### Development

As of Nov 2016 pfweb is under initial development. Use at your own risk.

## Dependencies

- [OpenBSD 6.0+](http://www.openbsd.org/): Only tested on OpenBSD 6.0 amd64
- [py-pf](http://www.kernel-panic.it/software/py-pf/): Python module for 
managing OpenBSD's Packet Filter
- [Flask](http://flask.pocoo.org/): A microframework for Python based on 
Werkzeug and Jinja 2
- [Flask-Login](https://flask-login.readthedocs.io/): User session management 
for Flask

## Installation

Installation under a virtualenv will work fine.

pfweb utilizes the well written 
[py-pf module](http://www.kernel-panic.it/software/py-pf/). The version in 
PyPi is not up to date so you'll need to clone from the 
[py-pf github repo](https://github.com/dotpy/py-pf) and install.

```sh
$ git clone https://github.com/dotpy/py-pf.git
$ cd py-pf
$ python setup.py install
```

pfweb is under heavy development right now, so it is probably best to clone 
from github. First install Flask and Flask-Login then install pfweb.

```sh
$ pip install Flask flask-login
$ git clone https://github.com/nahun/pfweb.git
$ cd pfweb
$ python setup.py install
```

Or if the version on PyPi is actually current you can use pip:

```sh
$ pip install pfweb
```

## Setup

After installation, you'll have to decide how you want to run it. There are 
many options for python web applications such as FastCGI, mod_wsgi, uWSGI, 
etc... You can refer to 
[Flask's documentation](http://flask.pocoo.org/docs/0.11/deploying/#deployment) 
for more detail, but this guide will concentrate on FastCGI, flup, and 
OpenBSD's httpd

### Install flup

You'll need to install [flup](https://pypi.python.org/pypi/flup/1.0.2), the 
FastCGI server:

```sh
$ pip install flup
```

### Create the FastCGI Server

Then you need to create a FastCGI server file such as *pfweb.fcgi*:

```python
from flup.server.fcgi import WSGIServer
import pfweb

if __name__ == '__main__':
    WSGIServer(pfweb.app, bindAddress='/var/www/run/pfweb.sock').run()
```

Make sure the socket file path is in httpd's chroot of /var/www otherwise 
httpd won't be able to read it.

### Setup httpd

Setup `/etc/httpd.conf` to use the fastcgi socket and listen on your IP. Edit 
the certificate paths with your own.

```
domain="example.com"

server $domain {
    listen on 1.2.3.4 port 80
    block return 301 "https://$SERVER_NAME$REQUEST_URI"
}

server $domain {
    listen on 1.2.3.4 tls port 443
    fastcgi socket "/run/pfweb.sock"

    tls {
        certificate "/etc/ssl/example.com.crt"
        key "/etc/ssl/private/example.com.key"
    }
}
```

Remember, httpd runs in a chroot under /var/www so set your fastcgi socket 
accordingly.

### PF Permissions

You'll need to give a user access to /dev/pf and /etc/pf.conf so we don't run 
anything as root. Create or use whichever group you want, we'll use *pfweb*. 
Also make sure the user running your webserver and FastCGI server is a member 
of that group.

```
# chown root:pfweb /dev/pf /etc/pf.conf
# chmod g+rw /dev/pf /etc/pf.conf
```

### Create a Config File

Now lets create the config file and username and password used to login to 
pfweb. The *pfweb.ini* file can exist at:

- ~/.pfweb.ini
- /etc/pfweb.ini
- /usr/local/etc/pfweb.ini

pfweb will choose from that order. There are two required parameters that you 
must set manually, the Flask *secret_key* used in sessions and a *salt* to hash 
the password we'll be setting for authentication. Create the pfweb.ini with 
random strings used for these two parameters.

```ini
[main]
secret_key = longrandomstring
salt = anotherrandomstring
```

### Create a Username and Password

There are a few ways we can accomplish creating the username and password:

#### 1. Use `create_user.py`

The script is distributed in the package so you will need to find it in your 
installation or just [download](create_user.py?raw=true) it from the 
repo.

```sh
$ python create_user.py
Enter username: admin
Enter Password:
Confirm Password:
User tester created successfully
```

#### 2. pfweb Config() manually

You can import the pfweb Config object and create the credentials manually:

```python
>>> from pfweb.config import Config
>>> c = Config()
>>> c.create_user('your_username', 'your_password')
```

#### 3. Manually hash your password

Using python you can hash your password and enter it in manually to the config 
file. This will hash the password the same way the Config.create_user() method 
does.

```python
>>> import hashlib, binascii
>>> salt='your_salt'
>>> password='your_password'
>>> dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
>>> binascii.hexlify(dk)
'26383a0418be31cb6906418b367e19eb404cb8296e8f03521244b21cc079b82c'
```

Copy that hash and paste it into your config file with your username:

```ini
[main]
secret_key = longrandomstring
salt = anotherrandomstring
username = admin
password = 26383a0418be31cb6906418b367e19eb404cb8296e8f03521244b21cc079b82c
```

### Run the servers

Run the FastCGI server and (re)start httpd. The httpd_flags="" command is 
obviously optional if you already have it running. Make sure to run the 
FastCGI server as the correct user that has access to PF.
```sh
$ python pfweb.fcgi
```

```
# echo httpd_flags="" >> /etc/rc.conf.local
# rcctl restart httpd
```

You should now be able be able to reach pfweb in your browser

## Considerations

### FastCGI Process Managers

Just as the 
[Flask docs](http://flask.pocoo.org/docs/0.11/deploying/fastcgi/#running-fastcgi-processes) 
say, you may want to use a process manager for your FastCGI server.
[Supervisor](http://supervisord.org/configuration.html#fcgi-program-x-section-settings) 
works and OpenBSD has a package. Install with `pkg_add supervisor` then create 
a config file at `/etc/supervisord.d/pfweb.ini`

```ini
[fcgi-program:pfweb]
socket=unix:///var/www/run/pfweb.sock
command=/path/to/python /path/to/pfweb.fcgi
socket_owner=www
user=www
process_name=%(program_name)s_%(process_num)02d
numprocs=5
autostart=true
autorestart=true
```

Edit `/etc/supervisord.conf` and uncomment the two lines at the end:

```ini
[include]
files = supervisord.d/*.ini
```

Restart supervisord and you should be good to go.

## Screenshots

### Home Dashboard:
![Dashboard](http://i.imgur.com/H51Eheg.png)

### Rules list:
![Rules](http://i.imgur.com/hvbV5B4.png)

### Add or edit a rule:
![Edit Rule](http://i.imgur.com/mCTbGKR.png)

### Tables list:
![Tables](http://i.imgur.com/gnvPpLq.png)