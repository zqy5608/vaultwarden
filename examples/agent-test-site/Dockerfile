FROM python:3.13-slim-bookworm@sha256:a5a7017efc5969e00ae2b91c8eb0631049a569652aa4ffc4501769049ae45c72

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir --require-hashes -r requirements.txt
COPY agent_test_site.py test_site_pages.py test_site_state.py ./
USER 10001:10001
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:18082/health',timeout=3).close()"
ENTRYPOINT ["python", "-m", "agent_test_site"]
CMD ["--origin", "https://agent-test.bo0lean.com", "--database", "/data/site.sqlite3", "--host", "0.0.0.0"]
