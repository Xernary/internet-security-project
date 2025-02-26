FROM ubuntu:20.04
WORKDIR /root

# Dependencies
RUN apt -y update && apt install -y gcc build-essential gcc-multilib make ncat iproute2 sudo vim #php

# Installation script
COPY ./main.c main.c
COPY ./utils.c utils.c
COPY ./Makefile_server Makefile
RUN make
RUN touch index.php # empty php server file
RUN /sbin/adduser root sudo

# Expose server port
EXPOSE 8080
EXPOSE 5555

# Start C Server 
CMD ["sh", "-c", "nc -lk 5555 -c ./main > /dev/null & bash"]

