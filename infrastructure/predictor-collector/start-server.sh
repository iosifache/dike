#!/usr/bin/env bash

# Wait for the volume to be mounted
until cd /opt/dike/codebase
do
    echo "Waiting.."
done

# Run the API server
cd /opt/dike/codebase
python servers/predictor-collector/app.py &

# Build the user interface
cd /opt/dike/codebase/servers/predictor-collector/user-interface
npm install
npm run-script build

# Run the server exposing the user interface
serve --cors --single --listen 443 --ssl-cert\
 /opt/dike/data/keystore/certificate.pem --ssl-key\
 /opt/dike/data/keystore/key.pem build