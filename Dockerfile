FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Le honeypot ne tourne jamais en root : même s'il est conçu pour être
# attaqué, une éventuelle RCE ne doit pas offrir le conteneur entier.
RUN useradd --create-home --shell /usr/sbin/nologin honeypot \
    && mkdir -p /app/logs \
    && chown -R honeypot:honeypot /app
USER honeypot

EXPOSE 8080

CMD ["gunicorn", "-c", "gunicorn.conf.py", "app:app"]
