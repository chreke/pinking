import os
import argparse
import logging
import getpass
from pathlib import Path
from aiohttp import web
from aiohttp.helpers import BasicAuth
from functools import partial
from .proxy import ipfs_proxy_handler


async def _proxy_handler(request, target_url, auth):
    """
    Intercept calls to ipfs and add auth header
    If request is an add request, calculate the file/directory size and append
    to multipart header.
    """
    return await ipfs_proxy_handler(request, target_url, auth=auth)


async def _cleanup():
    pass


def main(args):
    username = args.username
    if username is None:
        username = input("Username: ")

    password = args.password
    if password is None:
        password = getpass.getpass()

    # Set up logging
    logging.basicConfig(format='local proxy: %(asctime)s %(message)s',
                        datefmt='%m/%d/%Y %I:%M:%S %p',
                        level=args.loglvl,
                        filename=args.logfile)


    app = web.Application()
    basic_auth = BasicAuth(username, password)
    proxy_handler = partial(_proxy_handler, target_url=args.target_url,
                            auth=basic_auth)
    app.router.add_route('*', '/{path:.*?}', proxy_handler)
    try:
        web.run_app(app, host='0.0.0.0', port=args.listen_port)
    except KeyboardInterrupt:
        asyncio.get_event_loop().run_until_complete(_cleanup())
