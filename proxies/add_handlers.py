import json
import logging
from aiohttp import web
from pathlib import Path
from multidict import MultiDict
from collections import defaultdict
from proxy import ipfs_proxy_handler
from pin_handlers import add_pins


async def add_handler(request, ipfs_url, django_url):
    """
    Handler for any `ipfs add` requests
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
    headers = {'Authorization': auth}
    async with app['session'].request('GET', me_url, headers=headers) as resp:
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

    await add_pins([h for h, _, _ in base_hashes], 'recursive', ipfs_url,
                    django_url, auth)

    await proxy_resp.write_eof()
    return proxy_resp

