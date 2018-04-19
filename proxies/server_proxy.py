import os
import logging
import argparse
import aiohttp
from functools import partial
from pathlib import Path
from aiohttp import web

import auth_handlers
from auth_handlers import auth_and_lock, auth_handler

import pin_handlers
from pin_handlers import pin_add_handler, pin_rm_handler, pin_ls_handler
from pin_handlers import add_pins, rm_pins

import mfs_handlers
from mfs_handlers import files_rm_handler, files_ls_handler
from mfs_handlers import files_rewrite_handler, files_repin_rewrite_handler

import add_handlers
from add_handlers import add_handler

import ipns_handlers
from ipns_handlers import rewrite_key_handler

async def _on_startup(app):
    app['session'] = aiohttp.ClientSession()


async def _on_cleanup(app):
    await app['session'].close()


if __name__ == "__main__":
    lvl_map = {
        'DEBUG': logging.DEBUG, 'INFO': logging.INFO, 'WARNING': logging.WARNING,
        'ERROR': logging.ERROR, 'CRITICAL': logging.CRITICAL
    }
    parser = argparse.ArgumentParser(description='Run the pinking server proxy')
    parser.add_argument("--listen_port", help="set the listening port",
                        type=int, default=5002)
    parser.add_argument("--ipfs_port", help="set the ipfs port",
                        type=int, default=5001)
    parser.add_argument("--django_port", help="set the django port",
                        type=int, default=8000)
    parser.add_argument("--logfile", help="the optional output log file", type=str)
    parser.add_argument("--loglvl", help="the log level",
                        type=str, choices=list(lvl_map.keys()), default='INFO')
    parser.add_argument("--ssl_cert_path", help="use ssl certs at path", type=str)
    args = parser.parse_args()

    # Set up logging
    logging.basicConfig(format='server proxy: %(asctime)s %(message)s',
                        datefmt='%m/%d/%Y %I:%M:%S %p',
                        level=args.loglvl,
                        filename=args.logfile)

    if args.ssl_cert_path is not None and not os.path.exists(args.ssl_cert_path):
        print(f'SSL cert path {ssl_cert_path} doesn\'t exist')
        raise ValueError()

    ssl_context = None
    if args.ssl_cert_path is not None:
        ssl_cert_path = Path(args.ssl_cert_path)
        if not args.ssl_cert_path.exists():
            print(f'SSL cert path {ssl_cert_path} doesn\'t exist')
            raise ValueError()

        print(f'Trying to use ssl context from {ssl_cert_path}')
        fullchain_path = ssl_cert_path / 'fullchain.pem'
        privkey_path = ssl_cert_path / 'privkey.pem'
        if fullchain_path.exists() and privkey_path.exists():
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            ssl_context.load_cert_chain(fullchain_path, privkey_path)
        else:
            print('Fullchain or privkey didn\'t exist')
            raise ValueError()

    ipfs_url = f'http://127.0.0.1:{args.ipfs_port}'
    django_url = f'http://127.0.0.1:{args.django_port}'
    kwargs = {'ipfs_url': ipfs_url, 'django_url': django_url}
    app = web.Application()
    app.on_startup.append(_on_startup)
    app.on_cleanup.append(_on_cleanup)
    handlers = [pin_handlers, mfs_handlers, auth_handlers, add_handlers,
                ipns_handlers]
    for module in handlers:
        module.app = app

    routes = []
    # ----
    # Misc
    # ----
    routes.append((['add'], partial(add_handler, **kwargs)))

    # ----------------------------
    # Commands requiring auth only
    # ----------------------------
    auth_commands = ['cat', 'get', 'ls', 'refs', 'object/data',
                     'object/diff', 'object/get', 'object/links', 'object/new',
                     'object/patch/add-link', 'object/patch/append-data',
                     'object/patch/rm-link', 'object/patch/set-data',
                     'object/put', 'object/stat', 'version', 'tar/add',
                     'tar/cat', 'name/resolve']
    routes.append((auth_commands, auth_handler))

    # ----------
    # ipfs files
    # ----------
    files_rewrite_commands = ['files/flush', 'files/read', 'files/stat']
    routes.append((files_rewrite_commands, files_rewrite_handler))
    files_repin_rewrite_commands = ['files/cp', 'files/mkdir', 'files/mv',
                                    'files/write']
    routes.append((files_repin_rewrite_commands, files_repin_rewrite_handler))
    routes.append((['files/rm'], files_rm_handler))
    routes.append((['files/ls'], files_ls_handler))

    # --------
    # ipfs pin
    # --------
    routes.append((['pin/ls'], pin_ls_handler))
    routes.append((['pin/add'], pin_add_handler))
    routes.append((['pin/rm'], pin_rm_handler))


    # -------------------------------
    # ipfs key and ipfs name publish
    # -------------------------------
    routes.append((['key/list'], partial(rewrite_key_handler)))
    routes.append((['key/gen'], partial(rewrite_key_handler, key_argname='arg')))
    routes.append((['key/rename'], partial(rewrite_key_handler, key_argname='arg')))
    routes.append((['key/rm'], partial(rewrite_key_handler, key_argname='arg')))
    routes.append((['name/publish'], partial(rewrite_key_handler, key_argname='key')))

    for paths, handler in routes:
        for path in paths:
            wrapped = partial(auth_and_lock, handler=handler, handler_kwargs=kwargs)
            app.router.add_route('POST', f'/api/v0/{path}', wrapped)

    try:
        web.run_app(app, host='0.0.0.0', ssl_context=ssl_context, port=args.listen_port)
    except KeyboardInterrupt:
        pass
