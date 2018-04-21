import re
from setuptools import setup

try: # for pip >= 10
    from pip._internal.req import parse_requirements
except ImportError: # for pip <= 9.0.3
    from pip.req import parse_requirements

version = re.search('^__version__\s*=\s*"(.*)"',
                    open('pinking/__init__.py').read(),
                    re.M).group(1)

try:
    import pypandoc
    long_description = pypandoc.convert('README.md', 'rst')
except:
    long_description = open('README.md', 'r').read()


# parse_requirements() returns generator of pip.req.InstallRequirement objects
install_reqs = parse_requirements('requirements.txt', session='hack')
reqs = [str(ir.req) for ir in install_reqs]

setup(
    name="pinking",
    packages=["pinking", "pinking.pinking", "pinking.proxies", "pinking.users",
              "pinking.pin"],
    entry_points={"console_scripts": ['pinking = pinking:main']},
    version=version,
    description="IPFS proxy and pinning service",
    long_description=long_description,
    author="Martin Pettersson",
    author_email="martin@rememberberry.com",
    url="https://github.com/johnytex/pinking",
    install_requires=reqs
)
