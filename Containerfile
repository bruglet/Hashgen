FROM python:3-alpine

RUN --mount=type=secret,id=proxy_ca \
    if [ -f /run/secrets/proxy_ca ]; then \
        SSL_CERT_FILE=/run/secrets/proxy_ca apk add --no-cache tar xz 7zip; \
    else \
        apk add --no-cache tar xz 7zip; \
    fi

WORKDIR /app
COPY --chmod=644 requirements-windows.txt .
RUN --mount=type=secret,id=proxy_ca \
    if [ -f /run/secrets/proxy_ca ]; then \
        PIP_CERT=/run/secrets/proxy_ca pip install --no-cache-dir -r requirements-windows.txt; \
    else \
        pip install --no-cache-dir -r requirements-windows.txt; \
    fi
COPY --chmod=644 hasher.py windows_hasher.py .

VOLUME /data

ENTRYPOINT ["python3", "hasher.py"]
CMD ["update"]
