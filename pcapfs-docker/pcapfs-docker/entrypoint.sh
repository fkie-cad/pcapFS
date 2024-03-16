#!/bin/bash

sudo chmod -R 777 /opt/mountpoint
sudo chown -R pcapfs:pcapfs /opt/mountpoint

# Run the main process
exec "$@"