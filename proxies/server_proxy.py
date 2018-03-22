import os
import base64
import logging
import argparse
import aiohttp
import json
from functools import partial
from pathlib import Path
from aiohttp import web
from multidict import MultiDict
from proxy import ipfs_proxy_handler


def _get_user_password(request):
    basic_auth = request.headers.get('Authorization', None)
    if basic_auth:
        user_pass_bytes = base64.b64decode(basic_auth.split(' ')[1])
        return user_pass_bytes.decode('utf-8').split(':')
    return None, None


async def _authenticate(request):
    #
    # Check with Django
    #

    user, pwd = _get_user_password(request)
    if user is None or pwd is None:
        return web.Response(status=401)
    logging.info(f'Authenticating with {user} {pwd}')
    return None


async def _files_handler(request, target_url):
    """
    Handler for files requests (MFS). Authenticate user and then
    rewrite paths to keep within user sandbox
    """
    auth_response = await _authenticate(request)
    if auth_response is not None:
        return auth_response

    # Rewrite query paths
    username, pwd = _get_user_password(request)
    username_b64 = base64.b64encode(username.encode('utf-8')).decode('utf-8')
    new_query = MultiDict()
    for key, val in request.rel_url.query.items():
        if key in ['arg', 'arg2'] and not val.startswith('/ipfs/'):
            new_path = f'/{username_b64}{os.path.normpath(val)}'
            new_query.add(key, new_path)
        else:
            new_query.add(key, val)

    return await ipfs_proxy_handler(request, target_url, query=new_query)


async def _auth_handler(request, target_url):
    """
    Handler for any request that just needs authentication and nothing more
    """
    auth_response = await _authenticate(request)
    if auth_response is not None:
        return auth_response

    return await ipfs_proxy_handler(request, target_url)


async def _traverse_hashes(ipfs_hash, ipfs_url):
    # Get the block size of the hash
    collect_hashes = []
    stat_url = f'{ipfs_url}/api/v0/object/stat'
    async with aiohttp.ClientSession() as session:
        async with session.request('POST', stat_url, params={'arg': ipfs_hash}) as resp:
            if resp.status != 200:
                raise ValueError()
            block_size = json.loads(await resp.text())['BlockSize']
            collect_hashes.append((ipfs_hash, block_size))

    # Recusively traverse children
    links_url = f'{ipfs_url}/api/v0/object/links'
    async with aiohttp.ClientSession() as session:
        async with session.request('POST', links_url, params={'arg': ipfs_hash}) as resp:
            if resp.status != 200:
                raise ValueError()
            links = json.loads(await resp.text()).get('Links', None) or []
            for link in links:
                collect_hashes += await _traverse_hashes(link['Hash'], ipfs_url)

    return collect_hashes


async def _pin_ls_handler(request, target_url):
    pass


async def _pin_add_handler(request, target_url):
    auth_response = await _authenticate(request)
    if auth_response is not None:
        return auth_response

    ipfs_hash = request.rel_url.query.get('arg', None)
    if ipfs_hash is None:
        return web.Response(status=400)

    try:
        hashes = await _traverse_hashes(ipfs_hash, target_url)
    except:
        return web.Response(status=400)

    logging.info(hashes)

    #
    # Check with django here
    #

    return await ipfs_proxy_handler(request, target_url)


async def _pin_rm_handler(request, target_url):
    pass


async def _pin_update_handler(request, target_url):
    pass


async def _pin_verify_handler(request, target_url):
    pass


async def _cleanup():
    pass


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

    routes = []
    # -----------------------------
    # Commands requiring auth only
    # -----------------------------
    auth_handler = partial(_auth_handler, target_url=target_url)
    auth_commands = ['add', 'cat', 'get', 'ls', 'refs', 'object/data',
                     'object/diff', 'object/get', 'object/links', 'object/new',
                     'object/patch/add-link', 'object/patch/append-data',
                     'object/patch/rm-link', 'object/patch/set-data',
                     'object/put', 'object/stat', 'version', 'tar/add',
                     'tar/cat']
    routes.append((auth_commands, auth_handler))

    # ----------
    # ipfs files
    # ----------
    files_handler = partial(_files_handler, target_url=target_url)
    files_commands = ['chcid', 'cp', 'flush', 'ls', 'mkdir', 'mv', 'read',
                         'rm', 'stat', 'write']
    files_commands = [f'files/{command}' for command in files_commands]
    routes.append((files_commands, files_handler))

    # ---------
    # ipfs key
    # ---------
    '''
    key_handler = partial(_key_handler, target_url=target_url)
    routes.append(['key/gen'], _key_gen_handler)
    routes.append(['key/list'], _key_list_handler)
    routes.append(['key/rename'], _key_rename_handler)
    routes.append(['key/rm'], _key_rm_handler)
    '''

    # ---------
    # ipfs pin
    # ---------
    routes.append((['pin/ls'], partial(_pin_ls_handler, target_url=target_url)))
    routes.append((['pin/add'], partial(_pin_add_handler, target_url=target_url)))
    routes.append((['pin/rm'], partial(_pin_rm_handler, target_url=target_url)))
    routes.append((['pin/update'], partial(_pin_update_handler, target_url=target_url)))
    routes.append((['pin/verify'], partial(_pin_verify_handler, target_url=target_url)))
    for paths, handler in routes:
        for path in paths:
            app.router.add_route('POST', f'/api/v0/{path}', handler)

    try:
        web.run_app(app, host='0.0.0.0', ssl_context=ssl_context, port=args.listen_port)
    except KeyboardInterrupt:
        asyncio.get_event_loop().run_until_complete(_cleanup())
