FROM python:3.12-slim
RUN pip install --no-cache-dir cortexutils==2.2.1 requests
WORKDIR /worker
COPY cape_analyzer.py /worker/cape_analyzer.py
ENTRYPOINT ["python3", "/worker/cape_analyzer.py"]
