from setuptools import setup, find_packages
import codecs
import os

here = os.path.abspath(os.path.dirname(__file__))

with codecs.open(os.path.join(here, "README.md"), encoding="utf-8") as fh:
    long_description = "\n" + fh.read()

VERSION = '0.1.1'
DESCRIPTION = 'Python Project for Nmap-API with GPT integration'
LONG_DESCRIPTION = """
Uses python3.10, Debian, python-Nmap, and flask framework
to create a Nmap API that can do scans with a good speed
online and is easy to deploy. This is a implementation
for our college PCL project which is still under
development and constantly updating.
"""

# Setting up
setup(
    name="Nmap_API",
    version=VERSION,
    author="Chiranjeevi G",
    author_email="morpheuslord@protonmail.com",
    description=DESCRIPTION,
    long_description_content_type="text/markdown",
    long_description=long_description,
    packages=find_packages(),
    package_data={
        'nmap_api': ['nmap_api/auth_keys.db'],
    },
    install_requires=['aiohttp==3.8.4',
                      'aiosignal==1.3.1',
                      'aniso8601==9.0.1',
                      'async-timeout==4.0.2',
                      'attrs==22.2.0',
                      'autopep8==2.0.2',
                      'certifi==2022.12.7',
                      'charset-normalizer==3.1.0',
                      'click==8.1.3',
                      'colorama==0.4.6',
                      'Flask==2.2.3',
                      'Flask-RESTful==0.3.9',
                      'frozenlist==1.3.3',
                      'idna==3.4',
                      'itsdangerous==2.1.2',
                      'Jinja2==3.1.2',
                      'lxml==4.9.2',
                      'MarkupSafe==2.1.2',
                      'multidict==6.0.4',
                      'openai==0.27.4',
                      'pycodestyle==2.10.0',
                      'python-nmap==0.7.1',
                      'pytz==2023.3',
                      'requests==2.28.2',
                      'six==1.16.0',
                      'tomli==2.0.1',
                      'tqdm==4.65.0',
                      'urllib3==1.26.15',
                      'Werkzeug==2.2.3',
                      'yarl==1.8.2'],
    keywords=['python', 'GPT', 'vulnerability',
              'ai', 'vulnerability-assessment', 'network-scanning'],
    classifiers=[
        "Development Status :: 1 - Planning",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "Operating System :: Unix",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: Microsoft :: Windows",
    ]
)
