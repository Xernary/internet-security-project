FROM debian:bullseye
WORKDIR /root

# Dependencies
RUN apt -y  update && apt -y upgrade && apt install -y sudo vim curl iproute2 procps

# Installation script
COPY ./server-setup-script.sh server-setup-script.sh
RUN chmod +x server-setup-script.sh
RUN ./server-setup-script.sh
RUN ./startup.sh

# Expose server port
EXPOSE 8080

# Start Tomcat 
CMD ["sh", "-c", "./startup.sh && bash"]

