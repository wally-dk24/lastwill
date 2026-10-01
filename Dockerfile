# lastwill — dead-man's registry for scheduled automations.
# Credential-free: the HMAC key lives in the mounted state dir, never in the image.
# State: mount a host dir at /data and set LASTWILL_HOME=/data
#   docker run --rm -v ~/.lastwill:/data -e LASTWILL_HOME=/data wallydk24/lastwill audit
# RUN-free by design: builds for amd64/arm64/386 with no qemu or binfmt needed.
FROM python:3.12-alpine
COPY lastwill.py /usr/local/bin/lastwill.py
USER 1000
ENTRYPOINT ["python3", "/usr/local/bin/lastwill.py"]
