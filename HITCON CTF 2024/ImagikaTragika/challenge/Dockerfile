FROM python:3.12-slim-bookworm

# Install dependencies
RUN apt-get update && apt-get install -y gcc curl libfontconfig1 libx11-6 libharfbuzz0b libfribidi0 && \ 
    curl -fsSL https://imagemagick.org/archive/binaries/magick -o /bin/magick && \
    chmod +x /bin/magick && \
    pip install --no-cache-dir uvicorn python-multipart fastapi magika==0.5.1
# Make ImageMagick happy in the container
ENV APPIMAGE_EXTRACT_AND_RUN 1

# Make sure magick can be run without errors
RUN magick -version

RUN useradd -ms /bin/bash ctf

WORKDIR /home/ctf/app

# ImageMagick said we need to do this to enhance security
RUN mkdir -p /home/ctf/.config/ImageMagick/ && \
    curl -fsSL https://imagemagick.org/source/policy-secure.xml -o /home/ctf/.config/ImageMagick/policy.xml && \
    chmod -R a-w /home/ctf/.config/ && \
    chown -R ctf:ctf /home/ctf/.config/
# Setup challenge file
COPY ./src/ /home/ctf/app
RUN chown -R ctf:ctf /home/ctf/app

# Setup flag & readflag
COPY ./flag/readflag.c /readflag.c
COPY ./flag/flag /flag
RUN chmod 0400 /flag && chown root:root /flag
RUN chmod 0444 /readflag.c && gcc /readflag.c -o /readflag
RUN chown root:root /readflag && chmod 4555 /readflag

USER ctf
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "1337"]
