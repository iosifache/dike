# Set base image
FROM python

# Set working directory
WORKDIR /

# Add to Python path
ENV PYTHONPATH "${PYTHONPATH}:/dike/dike"

# Specify that the app will listen on a specific port
EXPOSE 1234

# Copy and run the startup script
COPY start-server.sh /
RUN ["chmod", "+x", "start-server.sh"]
CMD /start-server.sh