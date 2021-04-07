# Set base image
FROM python

# Set working directory
WORKDIR /

# Add to Python path
ENV PYTHONPATH "${PYTHONPATH}:/dike/dike"

# Copy and run the startup script
COPY start-server.sh /
RUN ["chmod", "+x", "start-server.sh"]
CMD /start-server.sh