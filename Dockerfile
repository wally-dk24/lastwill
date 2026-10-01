# lastwill — dead-man's registry for scheduled automations.
# Credential-free: the HMAC key lives in the mounted state dir, never in the image.
# State: mount a host dir at /data and set LASTWILL_HOME=/data
#   docker run --rm -v ~/.lastwill:/data -e LASTWILL_HOME=/data wallydk24/lastwill audit
FROM python:3.12-alpine
COPY lastwill.py /usr/local/bin/lastwill
RUN chmod +x /usr/local/bin/lastwill
ENTRYPOINT ["lastwill"]
