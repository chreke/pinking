"""
Handlers for IPNS (key and publishing) functionality
"""
import json
import base64
import asyncio
import logging
from aiohttp import web
from multidict import MultiDict
from collections import defaultdict
from proxy import ipfs_proxy_handler
from auth_handlers import get_user_password


async def rewrite_key_handler(request, ipfs_url, django_url, key_argname=None):
    """
    Rewrite key paths with a username prefix
    """
    username, _ = get_user_password(request)
    username_b64 = base64.b64encode(username.encode('utf-8')).decode('utf-8')
    if 'self' in request.query.getall(key_argname, 'self'):
        # Make sure the self key exists for this user
        gen_url = f'{ipfs_url}/api/v0/key/gen'
        # Gen key will fail if there already is one, but that's ok
        key_params = {'arg': f'{username_b64}-self', 'type': 'rsa', 'size': 2048}
        await app['session'].request('POST', gen_url, params=key_params)

    # Rewrite they key with username prefix
    new_query = MultiDict()
    for key, val in request.query.items():
        if key == key_argname:
            new_key = f'{username_b64}-{val}'
            new_query.add(key, new_key)
        else:
            new_query.add(key, val)

    # Set the default key as self
    if key_argname is not None and key_argname not in new_query:
        new_query[key_argname] = f'{username_b64}-self'

    async def _resp_chunk_transform(chunk):
        # Rewrite responses with keys in them
        try:
            chunk_json = json.loads(chunk.decode('utf-8'))
        except:
            return chunk
        user_prefix = f'{username_b64}-'
        if 'Keys' in chunk_json:
            new_chunk = {'Keys': []}
            for key in chunk_json['Keys']:
                if key['Name'].startswith(user_prefix):
                    new_key = {'Name': key['Name'][len(user_prefix):],
                               'Id': key['Id']}
                    new_chunk['Keys'].append(new_key)
            return json.dumps(new_chunk).encode('utf-8')
        elif 'Message' in chunk_json:
            chunk_json['Message'] = chunk_json['Message'].replace(user_prefix, '')
            return json.dumps(chunk_json).encode('utf-8')
        return chunk

    proxy_resp = await ipfs_proxy_handler(
        request, ipfs_url, query=new_query,
        resp_chunk_transform=_resp_chunk_transform, write_eof=False)
    await proxy_resp.write_eof()
    return proxy_resp
