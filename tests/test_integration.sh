#! /bin/bash

# This script launches two ipfs daemons with separate repositories and
# runs through ipfs client commands either directly to one of the daemons,
# or through local_proxy -> server_proxy, django -> ipfs daemon 2, and then
# compares the output for different tests

# Kill all ipfs processes and local/server proxy
ps -A | grep ipfs | awk '{print $1}' | xargs -I {} kill -9 {}
# Kill proxies
ps -A | grep local_proxy | awk '{print $1}' | xargs -I {} kill -9 {}
ps -A | grep server_proxy | awk '{print $1}' | xargs -I {} kill -9 {}
# Kill django
ps -A | grep runserver | awk '{print $1}' | xargs -I {} kill -9 {}

# Launch two ipfs daemons with different 
IPFS1=/tmp/.pinking_ipfs1
IPFS2=/tmp/.pinking_ipfs2
IPFS1_PORT=5001
IPFS2_PORT=5002
PRE=/ip4/127.0.0.1/tcp/
IPFS1_API=$PRE$IPFS1_PORT 
IPFS2_API=$PRE$IPFS2_PORT 
PROXY_PORT=5003
PROXY_API=$PRE$PROXY_PORT 
SERVER_PROXY_PORT=5004
DJANGO_PORT=8000
rm -rf $IPFS1 2> /dev/null
rm -rf $IPFS2 2> /dev/null
IPFS_PATH=$IPFS1 ipfs --api $IPFS1_API daemon --init > /dev/null 2>&1 &
IPFS_PATH=$IPFS2 ipfs --api $IPFS2_API init > /dev/null 2>&1
# Change the port of gateways so they don't collide
sed -i -e 's/8080/8081/g' $IPFS2/config
IPFS_PATH=$IPFS2 ipfs --api $IPFS2_API daemon > /dev/null 2>&1 &
sleep 10

# Flush the django database
python manage.py flush --noinput
# Create a super user account
echo "from django.contrib.auth.models import User; \
  User.objects.create_superuser('test', 'test@example.com', 'test')"\
  | python manage.py shell
python manage.py runserver > /dev/null & # 2>&1 &

python proxies/local_proxy.py --listen_port $PROXY_PORT \
                              --target_url http://127.0.0.1:$SERVER_PROXY_PORT \
                              -u test \
                              -p test & #> /dev/null 2>&1 &
python proxies/server_proxy.py --listen_port $SERVER_PROXY_PORT \
                               --ipfs_port $IPFS2_PORT \
                               --django_port $DJANGO_PORT & # > /dev/null 2>&1 &
sleep 3

function test {
  # Run command against both apis and compare
  OUT1=$(ipfs --api $IPFS1_API $1)
  OUT2=$(ipfs --api $PROXY_API $1)
  #echo $OUT1
  if [ "$OUT1" != "$OUT2" ]; then
    echo "$OUT1 != $OUT2"
    exit 1
  fi
  TEST_OUT=$OUT1
}

# First remove pins that automatically come with the repos
ipfs --api $IPFS1_API pin ls | grep recursive | cut -d " " -f 1 | xargs -I {} ipfs --api $IPFS1_API pin rm {}
ipfs --api $IPFS2_API pin ls | grep recursive | cut -d " " -f 1 | xargs -I {} ipfs --api $IPFS2_API pin rm {}

test "pin ls"

#Initialize a repository
echo "hello world" > testfile
test "add testfile"
HASH=$(echo $TEST_OUT | cut -d " " -f 2)
echo $HASH

sleep 1 # have to sleep a bit for the add pin to come through
test "pin ls"

# Kill all processes we started in the beginning
sleep 2
kill %1
kill %2
kill %3
kill %4
kill %5
