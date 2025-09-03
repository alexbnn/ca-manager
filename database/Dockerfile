FROM postgres:15-alpine

ENV POSTGRES_USER=pkiuser
ENV POSTGRES_PASSWORD=pkipass
ENV POSTGRES_DB=pkiauth


# Copy database initialization scripts into the image
COPY 01-schema.sql /docker-entrypoint-initdb.d/
COPY 02-initial-data.sql /docker-entrypoint-initdb.d/
COPY 03-tenant-schema.sql /docker-entrypoint-initdb.d/
COPY 04-ocsp-schema.sql /docker-entrypoint-initdb.d/
COPY 05-system-config.sql /docker-entrypoint-initdb.d/
COPY 06-intermediate-ca-schema.sql /docker-entrypoint-initdb.d/
COPY 07-email-verification.sql /docker-entrypoint-initdb.d/