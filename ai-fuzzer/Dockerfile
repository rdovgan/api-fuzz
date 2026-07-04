FROM python:3.12-slim

WORKDIR /app

# non-root for safety
RUN useradd -m -u 10001 fuzzer

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY *.py ./

# /data is the shared volume: /data/reports and /data/cache
RUN mkdir -p /data/reports /data/cache && chown -R fuzzer:fuzzer /data /app
USER fuzzer

ENV FUZZ_CACHE=/data/cache

ENTRYPOINT ["python", "main.py"]
CMD ["--help"]
