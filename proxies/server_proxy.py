import os
import base64
import logging
import argparse
import aiohttp
import json
import asyncio
from collections import defaultdict
from functools import partial
from pathlib import Path
from aiohttp import web
from multidict import MultiDict
from proxy import ipfs_proxy_handler

# TODO: fix this, already defined in pin.models.Pin but not sure how to import
PIN_TYPE_CHOICES = ['direct', 'recursive', 'indirect', 'mfs']


class StorageLimitExceeded(Exception):
    pass


def _get_user_password(request):
    basic_auth = request.headers.get('Authorization', None)
    if basic_auth:
        user_pass_bytes = base64.b64decode(basic_auth.split(' ')[1])
        return user_pass_bytes.decode('utf-8').split(':')
    return None, None


async def _authenticate(request, django_url):
    """
    Check with Django
    """
    resp = await app['session'].request(
        'GET', f'{django_url}/api/auth/', headers=request.headers)
    await asyncio.sleep(0.01)
    if resp.status != 200:
        error_msg = {'Message': await resp.text(), 'Code': 0, 'Type': 'error'}
        return web.json_response(error_msg, status=resp.status)
    return None


_locks = defaultdict(lambda: False)
async def _auth_and_lock(request, handler, handler_kwargs):
    auth_response = await _authenticate(request, handler_kwargs['django_url'])
    if auth_response is not None:
        return auth_response

    user, _ = _get_user_password(request)
    if _locks.get(user) == True:
        error_msg = {'Message': f'multiple simultaneous requests is not allowed',
                     'Code': 0, 'Type': 'error'}
        return web.json_response(error_msg, status=429)

    try:
        _locks[user] = True
        ret = await handler(request, **handler_kwargs)
        _locks[user] = False
        return ret
    except:
        _locks[user] = False
        raise

    _locks[user] = False


def _rewrite_files_paths(request, query=None):
    """
    Rewrites paths in requests to use the MFS user root
    """
    query = query if query is not None else request.query
    username, pwd = _get_user_password(request)
    username_b64 = base64.b64encode(username.encode('utf-8')).decode('utf-8')
    new_query = MultiDict()
    for key, val in query.items():
        if key in ['arg', 'arg2'] and not val.startswith('/ipfs/'):
            if val[0] not in ['/', '\\']:
                raise ValueError()
            new_path = f'/{username_b64}{os.path.normpath(val)}'
            new_query.add(key, new_path)
        else:
            new_query.add(key, val)
    return new_query


async def _files_rm_handler(request, ipfs_url, django_url):
    """
    A special handler for `files rm`, since it needs to return an error if
    trying to delete root
    """
    rm_paths = request.query.getall('arg', None)
    if '/' in rm_paths:
        error_msg = {'Message': f'cannot delete root', 'Code': 0, 'Type': 'error'}
        return web.json_response(error_msg, status=500)

    response = await _files_repin_rewrite_handler(request, ipfs_url, django_url)
    return response


async def _files_rewrite_handler(request, ipfs_url, django_url):
    """
    A handler for MFS commands that don't change any MFS structure, but only reads it
    The handler rewrites all access paths within MFS to use the MFS user root
    instead of the real root
    """
    try:
        new_query = _rewrite_files_paths(request)
    except ValueError:
        error_msg = {'Message': f'paths must start with a leading slash',
                     'Code': 0, 'Type': 'error'}
        return web.json_response(error_msg, status=500)

    return await ipfs_proxy_handler(request, ipfs_url, query=new_query)


async def _files_ls_handler(request, ipfs_url, django_url):
    """
    A handler for MFS ls. Here we need to handle the special case where
    `ipfs files ls` is called without an arg. This is implicitly assumed to be '/'
    by go-ipfs
    """
    new_query = None
    if 'arg' not in request.query:
        new_query = MultiDict()
        for key, val in request.query.items():
            new_query.add(key, val)
        new_query.add('arg', '/')

    try:
        new_query = _rewrite_files_paths(request, new_query)
    except ValueError:
        error_msg = {'Message': f'paths must start with a leading slash',
                     'Code': 0, 'Type': 'error'}
        return web.json_response(error_msg, status=500)
    return await ipfs_proxy_handler(request, ipfs_url, query=new_query)


async def _files_repin_rewrite_handler(request, ipfs_url, django_url):
    """
    A handler for MFS commands that do change the MFS structure. The general
    procedure is:
    1. Rewrite paths (like in _files_rewrite_handler)
    2. Get the hash of the current MFS user root
        * Create the user root if it doesn't exist
    3. Proxy the request to IPFS
        * Make sure to rewrite any errors containing the user root folder,
          we don't want that to leak out.
    4. Get the new MFS user root hash
    5. Update the django database
        1. If this fails, roll back to previous root hash (e.g. if out of storage)
    """
    username, pwd = _get_user_password(request)
    username_b64 = base64.b64encode(username.encode('utf-8')).decode('utf-8')

    # Get the MFS user root hash
    files_url = f'{ipfs_url}/api/v0/files'
    resp = await app['session'].request(
        'POST', f'{files_url}/stat', params={'arg': f'/{username_b64}'})
    if resp.status != 200:
        if (await resp.json())['Message'] == 'file does not exist':
            # Create the user root if it doesn't exist
            resp = await app['session'].request(
                'POST', f'{files_url}/mkdir', params={'arg': f'/{username_b64}'})
        else:
            return web.Response(status=resp.status, text=text)
    resp_json = await resp.json()
    prev_root_hash = None if resp_json is None else resp_json['Hash']

    async def _resp_chunk_transform(chunk):
        """
        Rewrite any errors in the return message with the user root in them, 
        e.g. "/{user_root}/folder is a directory, use -r to remove directories" 
        to become "/folder is a directory, use -r to remove directories" 
        """
        try:
            chunk_json = json.loads(chunk.decode('utf-8'))
            user_root = f'/{username_b64}'
            msg = chunk_json['Message']
            if msg.startswith(user_root):
                chunk_json['Message'] = msg[len(user_root):]
            return json.dumps(chunk_json).encode('utf-8') + b'\n'
        except:
            return chunk

    # Proxy the request to ipfs
    try:
        new_query = _rewrite_files_paths(request)
    except ValueError:
        error_msg = {'Message': f'paths must start with a leading slash',
                     'Code': 0, 'Type': 'error'}
        return web.json_response(error_msg, status=500)
    response = await ipfs_proxy_handler(
        request, ipfs_url, query=new_query, write_eof=False,
        resp_chunk_transform=_resp_chunk_transform)
    if response.status != 200:
        await response.write_eof()
        return response

    # Read the new root hash
    resp = await app['session'].request(
        'POST', f'{files_url}/stat', params={'arg': f'/{username_b64}'})
    if resp.status != 200:
        await response.write_eof()
        return web.Response(status=resp.status, text=await resp.text())
    new_root_hash = (await resp.json())['Hash']

    # Update the database if the root hash changed
    error_response = None
    if new_root_hash != prev_root_hash:
        # TODO: this would be better done in one transaction
        auth = request.headers['Authorization']
        if prev_root_hash is not None:
            error_response = await _rm_pins(
                [prev_root_hash], ipfs_url, django_url, auth, include_mfs=True)
        # There seems to be a bug in ClientSession where two quick consecutive requests
        # to django here, the socket fails with "[Errno 54] Connection reset by peer"
        # We can fix this by sleeping for a bit, or using a fresh ClientSession
        await asyncio.sleep(0.01)
        error_response = await _add_pins(
            [new_root_hash], 'mfs', ipfs_url, django_url, auth)

        # If there was an error (e.g. out of storage), then roll back to previous
        # user root hash
        # TODO: can we do this in one step with files/write?
        if error_response is not None:
            await app['session'].request(
                'POST', f'{files_url}/rm', params={'arg': f'/{username_b64}'})
            if prev_root_hash is not None:
                await app['session'].request(
                    'POST', f'{files_url}/cp',
                    params={'arg': f'/ipfs/{prev_root_hash}', 'arg2': f'/{username_b64}'})

    await response.write_eof()
    if error_response is not None:
        return error_response
    return response


async def _auth_handler(request, ipfs_url, django_url):
    return await ipfs_proxy_handler(request, ipfs_url)


async def _add_handler(request, ipfs_url, django_url):
    """
    Handler for any request that just needs authentication and nothing more
    """
    auth = request.headers['Authorization']

    forbidden_options = ['raw-leaves', 'nocopy', 'fscache']
    for opt in forbidden_options:
        if request.query.get(opt, 'false') != 'false':
            error_msg = {'Message': f'"--{opt} is an experimental option not supported by pinking"',
                         'Code': 0, 'Type': 'error'}
            return web.json_response(error_msg, status=500)

    do_pin = request.query.get('pin', 'true') == 'true'
    if not do_pin:
        # If the user only doesn't want to pin then no limits apply, just
        # let it through
        return await ipfs_proxy_handler(request, ipfs_url)

    # Make a new query dict with pin=false (we dont want ipfs to pin it recursively,
    # we'll handle that manually)
    new_query = MultiDict()
    for key, val in request.query.items():
        if key == 'pin':
            new_query.add(key, 'false')
        else:
            new_query.add(key, val)

    me_url = f'{django_url}/api/me/'
    async with app['session'].request('GET', me_url, headers={'Authorization': auth}) as resp:
        resp_json = json.loads(await resp.text())[0]
        space_left = resp_json['space_total'] - resp_json['space_used']

    # Set a request chunk callback to check whether storage limit is ever exceeded
    storage_limit_exceeded = False
    space_left_resp = space_left
    last_size = defaultdict(lambda: 0)
    base_hashes = []
    async def _resp_chunk_transform(chunk):
        nonlocal space_left_resp, storage_limit_exceeded, base_hashes
        lines = chunk.split(b'\n')
        new_lines = []
        for line in lines:
            try:
                line_json = json.loads(line.decode('utf-8'))
            except:
                new_lines.append(line)
                continue

            if 'Bytes' in line_json:
                space_left_resp -= line_json['Bytes'] - last_size[line_json['Name']]
                last_size[line_json['Name']] = line_json['Bytes']
                if space_left_resp < 0:
                    storage_limit_exceeded = True
            elif 'Hash' in line_json:
                num_parts = len([p for p in Path(line_json['Name']).parts
                                 if p not in ['/', '\\']])

                if len(base_hashes) > 0 and base_hashes[0][2] > num_parts:
                    base_hashes = []

                base_hashes.append((line_json['Hash'], line_json['Name'], num_parts))
                if storage_limit_exceeded:
                    line_json['Hash'] = 'PIN FAILED: STORAGE LIMIT EXCEEDED'

            new_lines.append(json.dumps(line_json).encode('utf-8'))
        return b'\n'.join(new_lines)

    # NOTE: don't write eof in the handler, since then the response would be over
    # but we still need to add the pins to django before we want to return
    proxy_resp = await ipfs_proxy_handler(
        request, ipfs_url, query=new_query,
        resp_chunk_transform=_resp_chunk_transform, write_eof=False)

    if len(base_hashes) > 1:
        # Special case, need to wrap the files in a directory
        new_obj_url = f'{ipfs_url}/api/v0/object/new'
        add_link_url = f'{ipfs_url}/api/v0/object/patch/add-link'
        params = {'arg': 'unixfs-dir'}
        async with app['session'].request('GET', new_obj_url, params=params) as resp:
            if resp.status != 200:
                return web.Response(status=resp.status, text=await resp.text())

            resp_json = json.loads(await resp.text())
            dir_hash = resp_json['Hash']
            for multihash, name, _ in base_hashes:
                link_params = MultiDict()
                link_params.add('arg', dir_hash)
                link_params.add('arg', name)
                link_params.add('arg', multihash)
                resp = await app['session'].request('GET', add_link_url, params=link_params)
                resp_json = json.loads(await resp.text())
                dir_hash = resp_json['Hash']

            base_hashes = [(dir_hash, None, None)]

    await _add_pins([h for h, _, _ in base_hashes], 'recursive', ipfs_url,
                    django_url, auth)

    await proxy_resp.write_eof()
    return proxy_resp



async def _pins_from_multihash(multihash, ipfs_url, pin_type, first=True):
    """
    Recursively applies `ipfs object links` to get all downstream hashes and
    their block sizes. Note: one could use `ipfs refs --recursive` but it
    is slower due to probably downloading the data, or traversing block hashes
    """
    refs = []
    stat_url = f'{ipfs_url}/api/v0/object/stat'
    links_url = f'{ipfs_url}/api/v0/object/links'
    resp = await app['session'].request('POST', stat_url, params={'arg': multihash})
    if resp.status != 200:
        return resp
    block_size = json.loads(await resp.text())['BlockSize']
    refs.append({'multihash': multihash, 'block_size': block_size,
                 'pin_type': pin_type if first else 'indirect'})

    resp = await app['session'].request('POST', links_url, params={'arg': multihash})

    if resp.status != 200:
        return resp

    # Recusively traverse children
    links = json.loads(await resp.text()).get('Links', None) or []
    for link in links:
        ret = await _pins_from_multihash(
            link['Hash'], ipfs_url, pin_type, first=False)
        if not isinstance(ret, list):
            return ret
        refs += ret

    return refs


async def _get_pins_django(django_url, auth, include_mfs=False):
    pins_url = f'{django_url}/api/pins/'
    headers = {'Authorization': auth}
    await asyncio.sleep(0.01)
    async with app['session'].request('GET', pins_url, headers=headers) as resp:
        if resp.status != 200:
            return resp
        pins = json.loads(await resp.text())

        # Massage pins to the ipfs api format
        out_pins = defaultdict(list)
        for pin in pins:
            pin_type = PIN_TYPE_CHOICES[pin['pin_type']]
            if pin_type == 'mfs' and not include_mfs:
                continue
            out_pins[pin['multihash']].append(pin_type)

        return out_pins


async def _add_pins_django(pins, django_url, auth):
    for pin in pins:
        pin['pin_type'] = PIN_TYPE_CHOICES.index(pin['pin_type'])
    pins_url = f'{django_url}/api/pins/'
    headers = {'Authorization': auth}
    await asyncio.sleep(0.01)
    return await app['session'].request('POST', pins_url, headers=headers, json=pins)


async def _delete_pins_django(pins, django_url, auth):
    for pin in pins:
        if 'block_size' in pin:
            del pin['block_size']
        pin['pin_type'] = PIN_TYPE_CHOICES.index(pin['pin_type'])

    pins_url = f'{django_url}/api/delete-pins/'
    headers = {'Authorization': auth}
    await asyncio.sleep(0.01)
    return await app['session'].request('POST', pins_url, headers=headers, json=pins)


async def _pin_ls_handler(request, ipfs_url, django_url):
    """
    Get the pins from django/the database and return them
    """
    auth = request.headers['Authorization']
    ret = await _get_pins_django(django_url, auth)
    if not isinstance(ret, dict):
        return web.Response(status=ret.status, text=await ret.text())

    ipfs_format_pins = {'Keys': {}}
    for multihash, pin_types in ret.items():
        winning_pin_type = None
        if 'recursive' in pin_types:
            winning_pin_type = 'recursive'
        elif 'indirect' in pin_types:
            winning_pin_type = 'indirect'
        elif 'direct' in pin_types:
            winning_pin_type = 'direct'

        ipfs_format_pins['Keys'][multihash] = {'Type': winning_pin_type}
    return web.json_response(ipfs_format_pins)


async def _add_pins(multihash_args, pin_type, ipfs_url, django_url, auth):
    # Get pins from django
    ret = await _get_pins_django(django_url, auth, include_mfs=(pin_type=='mfs'))
    if not isinstance(ret, dict):
        return web.Response(status=ret.status, text=await ret.text())
    django_pins = ret

    # If any one of the pins fails, need to return error, and not pin any of
    # the other hashes
    for multihash in multihash_args:
        django_pin_types = django_pins.get(multihash, [])
        if pin_type == 'direct' and 'recursive' in django_pin_types:
            error_msg = {'Message': f'pin: {multihash} already pinned recursively',
                         'Code': 0, 'Type': 'error'}
            return web.json_response(error_msg, status=500)

    add_pins = []
    delete_pins = []
    for multihash in multihash_args:
        django_pin_types = django_pins.get(multihash, [])
        if pin_type in django_pin_types:
            # Do nothing, just return the multihash
            pass
        else:
            ret = await _pins_from_multihash(multihash, ipfs_url, pin_type)
            if not isinstance(ret, list):
                return web.Response(status=ret.status, text=await ret.text())
            pins = ret
            if pin_type == 'recursive' and 'direct' in django_pin_types:
                # If we're replacing a direct with recursive, delete the direct one
                delete_pins.append({'multihash': multihash, 'pin_type': 'direct'})
            add_pins += pins

    # Add new pins to ipfs as direct pins 
    pin_url = f'{ipfs_url}/api/v0/pin/add'
    pin_params = MultiDict()
    for pin in add_pins:
        pin_params['arg'] = pin['multihash']

    async with app['session'].request('POST', pin_url, params=pin_params) as resp:
        if resp.status != 200:
            return web.Response(status=resp.status, text=await resp.text())

    # Add new pins to django
    # NOTE: if this fails, we should roll back the direct pins we added to ipfs
    # but we can also let the garbage collector take care of it
    if len(add_pins) > 0:
        resp = await _add_pins_django(add_pins, django_url, auth)
        if resp.status != 201:
            return web.Response(status=resp.status, text=await resp.text())

    # Delete replaced pins (this will not affect disk usage, since duplicates
    # shouldn't count)
    if len(delete_pins) > 0:
        await _delete_pins_django(delete_pins, django_url, auth)


async def _pin_add_handler(request, ipfs_url, django_url):
    multihash_args = request.query.getall('arg', [])
    pin_type = ('recursive' if request.query.get('recursive', 'true') == 'true'
                else 'direct')
    auth = request.headers['Authorization']
    ret = await _add_pins(multihash_args, pin_type, ipfs_url, django_url, auth)
    if ret is not None:
        return ret
    return web.json_response({'Pins': multihash_args})


async def _rm_pins(multihash_args, ipfs_url, django_url, auth, include_mfs=False):
    ret = await _get_pins_django(django_url, auth, include_mfs=include_mfs)
    if not isinstance(ret, dict):
        return web.Response(status=ret.status, text=await ret.text())
    django_pins = ret
    
    delete_pins = []
    for multihash in multihash_args:
        if multihash not in django_pins:
            msg = {'Message': 'not pinned', 'Code': 0, 'Type': 'error'}
            return web.json_response(msg, status=500)
        pin_types_django = django_pins[multihash]
        recursive_types = list(set(pin_types_django) & set(['recursive', 'mfs']))
        if len(recursive_types) > 0:
            ret = await _pins_from_multihash(multihash, ipfs_url, recursive_types[0])
            if not isinstance(ret, list):
                return web.Response(status=ret.status, text=await ret.text())
            delete_pins += ret
        elif 'direct' in pin_types_django:
            delete_pins.append({'multihash': multihash, 'pin_type': 'direct'})
        else:
            # TODO: The real message from IPFS is:
            # "{h1} is pinned indirectly under {h2}"
            # We don't currently store which recursive pin owns which indirect pin
            # though, so for now:
            msg = {
                'Message': f'{multihash} is pinned indirectly under another pin',
                'Code': 0,
                'Type': 'error'
            }
            return web.json_response(msg, status=500)
    
    if len(delete_pins) > 0:
        await _delete_pins_django(delete_pins, django_url, auth)


async def _pin_rm_handler(request, ipfs_url, django_url):
    """
    Remove pins by first getting all user pins from django, then
    figure out the type of the pin to be removed and which indirect (if any)
    pins that should also be removed
    """
    multihash_args = request.query.getall('arg', [])

    auth = request.headers['Authorization']
    ret = await _rm_pins(multihash_args, ipfs_url, django_url, auth)
    if ret is not None:
        return ret
    return web.json_response({'Pins': multihash_args})


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

    routes = []
    # ----
    # Misc
    # ----
    add_handler = partial(_add_handler, **kwargs)
    routes.append((['add'], partial(_add_handler, **kwargs)))

    # ----------------------------
    # Commands requiring auth only
    # ----------------------------
    auth_commands = ['cat', 'get', 'ls', 'refs', 'object/data',
                     'object/diff', 'object/get', 'object/links', 'object/new',
                     'object/patch/add-link', 'object/patch/append-data',
                     'object/patch/rm-link', 'object/patch/set-data',
                     'object/put', 'object/stat', 'version', 'tar/add',
                     'tar/cat']
    routes.append((auth_commands, _auth_handler))

    # ----------
    # ipfs files
    # ----------
    files_rewrite_commands = ['files/flush', 'files/read', 'files/stat']
    routes.append((files_rewrite_commands, _files_rewrite_handler))
    files_repin_rewrite_handler = _files_repin_rewrite_handler
    files_repin_rewrite_commands = ['files/cp', 'files/mkdir', 'files/mv',
                                    'files/write']
    routes.append((files_repin_rewrite_commands, files_repin_rewrite_handler))
    routes.append((['files/rm'], _files_rm_handler))
    routes.append((['files/ls'], _files_ls_handler))
    # ---------
    # ipfs key
    # ---------
    '''
    key_handler = partial(_key_handler, ipfs_url=ipfs_url)
    routes.append(['key/gen'], _key_gen_handler)
    routes.append(['key/list'], _key_list_handler)
    routes.append(['key/rename'], _key_rename_handler)
    routes.append(['key/rm'], _key_rm_handler)
    '''

    # --------
    # ipfs pin
    # --------
    routes.append((['pin/ls'], _pin_ls_handler))
    routes.append((['pin/add'], _pin_add_handler))
    routes.append((['pin/rm'], _pin_rm_handler))


    # -------------------------------------
    # API commands that are not implemented
    # -------------------------------------
    #not_implemented_handler = partial(_not_implemented_handler, **kwargs)
    #not_implemented_commands = []
    #routes.append((not_implemented_commands, not_implemented_handler))


    for paths, handler in routes:
        for path in paths:
            wrapped = partial(_auth_and_lock, handler=handler, handler_kwargs=kwargs)
            app.router.add_route('POST', f'/api/v0/{path}', wrapped)

    try:
        web.run_app(app, host='0.0.0.0', ssl_context=ssl_context, port=args.listen_port)
    except KeyboardInterrupt:
        pass
