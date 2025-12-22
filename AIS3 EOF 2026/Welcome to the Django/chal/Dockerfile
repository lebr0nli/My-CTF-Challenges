FROM python:3.14-slim-trixie

# Set up the flag
COPY flag /flag
RUN target_dir="/flag_$(tr -dc A-Za-z0-9 </dev/urandom | head -c32)" && \
    mkdir -p "$target_dir" && \
    mv /flag "$target_dir/flag" && \
    chmod 444 "$target_dir/flag"

# Set up the application
RUN useradd -ms /bin/bash ctf
COPY --chown=ctf:ctf src /app
WORKDIR /app
USER ctf
RUN pip install --no-cache-dir django==6.0 gunicorn==23.0.0

CMD ["python", "-m", "gunicorn", "-b", "0.0.0.0:1337", "core.wsgi:application", "--workers", "4", "--threads", "4"]
