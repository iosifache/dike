#!/usr/bin/env bash

# Wait for the volume to be mounted
until cd /opt/dike/codebase
do
    echo "Waiting.."
done

# Run the subordinate server
cd /opt/dike/codebase
python servers/subordinate/app.py