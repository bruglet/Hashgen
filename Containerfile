FROM python:3-alpine

RUN apk add --no-cache tar xz

WORKDIR /app
COPY hasher.py .

VOLUME /data

ENTRYPOINT ["python3", "hasher.py"]
CMD ["update"]
