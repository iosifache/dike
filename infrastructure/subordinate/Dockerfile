# Set the base image
FROM python

# Set the working directory
WORKDIR /

# Expose the used ports
EXPOSE 3804

# Install OpenJDK
RUN apt-get update
RUN apt-get -y install openjdk-11-jdk-headless

# Install the Python3 requirements
ADD requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt

# Add the codebase to the Python path
ENV PYTHONPATH "${PYTHONPATH}:/opt/dike/codebase"

# Modify the OpenSSL configuration to support TLS 1.0/1.1
RUN sed -i "1s/^/openssl_conf = default_conf\n\n/" /etc/ssl/openssl.cnf
RUN echo -e "\n\n[ default_conf ]\nssl_conf = ssl_sect\n\n[ssl_sect]\n\
system_default = ssl_default_sect\n\n[ssl_default_sect]\nMinProtocol = None\n\
CipherString = DEFAULT:@SECLEVEL=1\n" >> /etc/ssl/openssl.cnf

# Run the startup script
COPY start-server.sh /
RUN chmod +x start-server.sh
CMD /start-server.sh