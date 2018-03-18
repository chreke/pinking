import argparse
import logging
from functools import partial
from pathlib import Path
from aiohttp import web
from proxy import ipfs_proxy_handler, run_proxy


async def _files_handler(request, target_url):
    """
    Handler for files requests (MFS). Authenticate user and then
    rewrite paths to keep within user sandbox
    """
    return await ipfs_proxy_handler(request, target_url)


async def _auth_handler(request, target_url):
    """
    Handler for any request that just needs authentication and nothing more
    """
    return await ipfs_proxy_handler(request, target_url)


if __name__ == "__main__":
    lvl_map = {
        'DEBUG': logging.DEBUG, 'INFO': logging.INFO, 'WARNING': logging.WARNING,
        'ERROR': logging.ERROR, 'CRITICAL': logging.CRITICAL
    }
    parser = argparse.ArgumentParser(description='Run the pinking server proxy')
    parser.add_argument("--listen_port", help="set the listening port",
                        type=int, default=5002)
    parser.add_argument("--target_port", help="set the target port",
                        type=int, default=5001)
    parser.add_argument("--logfile", help="the optional output log file", type=str)
    parser.add_argument("--loglvl", help="the log level",
                        type=str, choices=list(lvl_map.keys()), default='INFO')
    parser.add_argument("--ssl_cert_path", help="use ssl certs at path", type=str)
    args = parser.parse_args()

    # Set up logging
    logging.basicConfig(format='%(asctime)s %(message)s',
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

    target_url = f'http://127.0.0.1:{args.target_port}'
    app = web.Application()

    # ----------
    # auth only
    # ----------
    auth_handler = partial(_auth_handler, target_url=target_url)
    auth_commands = ['add', 'cat', 'get', 'ls', 'refs']
    for command in auth_commands:
        app.router.add_route('POST', f'/api/v0/{command}', auth_handler)

    # ----------
    # ipfs files
    # ----------
    files_handler = partial(_files_handler, target_url=target_url)
    files_subcommands = ['chcid', 'cp', 'flush', 'ls', 'mkdir', 'mv', 'read',
                         'rm', 'stat', 'write']
    for subcommand in files_subcommands:
        app.router.add_route('POST', f'/api/v0/files/{subcommand}', files_handler)
    try:
        web.run_app(app, host='0.0.0.0', ssl_context=ssl_context, port=args.listen_port)
    except KeyboardInterrupt:
        asyncio.get_event_loop().run_until_complete(cleanup())
