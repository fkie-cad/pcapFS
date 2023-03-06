# Docker compose and docker environment for quick and easy usage:

1. Build a docker image locally for yourself:

```
sudo docker compose build
```

2. Then launch the image:

```
sudo docker run --rm --device /dev/fuse --cap-add SYS_ADMIN --security-opt apparmor:unconfined --volume $(pwd)/datastore:/datastore pcapfs-docker_pcapfs /bin/bash -c 'sudo pcapFS/build/pcapfs -f -k /datastore/ssl.key /datastore/system-tests.pcap /datastore/mountpoints'
```

It is also possible to run another program and then execute all your work inside the docker environment without bind-mounted volumes.
This is basically just an idea how to build a container that has all dependencies correctly built for easy use.
