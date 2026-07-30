# Stdlib only — there is no pip install, so there is no dependency to drift or to patch. The whole
# app is three Python files and one HTML page.
FROM python:3.12-slim
WORKDIR /app
COPY app.py api.py store.py ./
COPY static/ ./static/
ENV PORT=8080 PYTHONUNBUFFERED=1
EXPOSE 8080
# Deliberately not root: the flaws in this app are application-logic flaws, and a lab that also
# hands out a root container teaches the wrong lesson about why the band-aid was needed.
RUN useradd --create-home --shell /usr/sbin/nologin larkspur
USER larkspur
HEALTHCHECK --interval=30s --timeout=3s --start-period=3s \
  CMD python3 -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/api/health',timeout=2).status==200 else 1)"
CMD ["python3", "app.py"]
