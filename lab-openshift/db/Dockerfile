FROM postgres:15-alpine

ENV POSTGRES_DB=labdb
ENV POSTGRES_USER=labuser
ENV POSTGRES_PASSWORD=labpass

COPY init.sql /docker-entrypoint-initdb.d/