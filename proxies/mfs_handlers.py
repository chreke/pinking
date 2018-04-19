import os
import json
import base64
import asyncio
import logging
from multidict import MultiDict
from aiohttp import web
from proxy import ipfs_proxy_handler
from auth_handlers import get_user_password
from pin_handlers import add_pins, rm_pins


def _rewrite_files_paths(request, query=None):
    """
    Rewrites paths in requests to use the MFS user root
    """
    query = query if query is not None else request.query
    username, _ = get_user_password(request)
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


async def files_rm_handler(request, ipfs_url, django_url):
    """
    A special handler for `files rm`, since it needs to return an error if
    trying to delete root
    """
    rm_paths = request.query.getall('arg', None)
    if '/' in rm_paths:
        error_msg = {'Message': f'cannot delete root', 'Code': 0, 'Type': 'error'}
        return web.json_response(error_msg, status=500)

    response = await files_repin_rewrite_handler(request, ipfs_url, django_url)
    return response


async def files_rewrite_handler(request, ipfs_url, django_url):
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


async def files_ls_handler(request, ipfs_url, django_url):
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


async def files_repin_rewrite_handler(request, ipfs_url, django_url):
    """
    A handler for MFS commands that do change the MFS structure. The general
    procedure is:
    1. Rewrite paths (like in files_rewrite_handler)
    2. Get the hash of the current MFS user root
        * Create the user root if it doesn't exist
    3. Proxy the request to IPFS
        * Make sure to rewrite any errors containing the user root folder,
          we don't want that to leak out.
    4. Get the new MFS user root hash
    5. Update the django database
        1. If this fails, roll back to previous root hash (e.g. if out of storage)
    """
    username, pwd = get_user_password(request)
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
            error_response = await rm_pins(
                [prev_root_hash], ipfs_url, django_url, auth, include_mfs=True)
        # There seems to be a bug in ClientSession where two quick consecutive requests
        # to django here, the socket fails with "[Errno 54] Connection reset by peer"
        # We can fix this by sleeping for a bit, or using a fresh ClientSession
        await asyncio.sleep(0.01)
        error_response = await add_pins(
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
