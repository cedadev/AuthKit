try:
    from setuptools import setup, find_packages
except ImportError:
    from ez_setup import use_setuptools
    use_setuptools()
    from setuptools import setup, find_packages

import sys, os

def read(*rnames):
    return open(os.path.join(os.path.dirname(__file__), *rnames)).read()

long_description = (
    "\n"+read('docs/index.txt')
    + '\n'
    + read('CHANGELOG.txt')
    + '\n'
    + read('LICENSE.txt')
    + '\n'
    'Download\n'
    '========\n'
)

version = '0.4.5'

setup(
    name="AuthKit",
    version=version,
    description='An authentication and authorization toolkit for WSGI applications and frameworks',
    long_description=long_description,
    license = 'MIT',
    author='James Gardner',
    author_email='james@pythonweb.org',
    url='http://authkit.org/',
    packages=find_packages(exclude=['test', 'examples', 'docs']),
    include_package_data=True,
    zip_safe=False,
    test_suite = 'nose.collector',
    install_requires = [
        "Paste>=1.4", "nose>=0.9.2", "PasteDeploy>=1.1", "Beaker>=1.1",
        "PasteScript>=1.1", "python-openid>=2.1.1", 
        "elementtree>=1.2,<=1.3", "decorator>=2.1.0",
        "WebOb>=0.9.3",
    ],
    extras_require = {
        'pylons': ["Pylons>=0.9.5,<=1.0"],
        'full': [
            "Pylons>=0.9.5,<=1.0", 
            "SQLAlchemy>=0.5.0,<=0.5.99", 
            "pudge==0.1.3", 
            "buildutils==dev", 
            "pygments>=0.7", 
            "TurboKid==0.9.5"
        ],
        'pudge': [
            "pudge==0.1.3", 
            "buildutils==dev", 
            "pygments>=0.7", 
            "TurboKid==0.9.5"
        ],
    },
    entry_points="""
        [authkit.method]
        basic=authkit.authenticate.basic:make_basic_handler
        digest=authkit.authenticate.digest:make_digest_handler
        form=authkit.authenticate.form:make_form_handler
        forward=authkit.authenticate.forward:make_forward_handler
        openid=authkit.authenticate.open_id:make_passurl_handler
        redirect=authkit.authenticate.redirect:make_redirect_handler
        cookie=authkit.authenticate.cookie:make_cookie_handler
        
        cas = authkit.authenticate.sso.cas:make_cas_handler

        [paste.paster_create_template]
        authenticate_plugin=authkit.template:AuthenticatePlugin
    """,
)
