# syntax=docker/dockerfile:1
# The TTP service: the trained model behind the API the hub calls (POST /api/v1/predict).
# The model bundle is NOT in the image; docker-compose mounts the repo's models/ folder at /models.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 NLTK_DATA=/usr/local/share/nltk_data
WORKDIR /app

# torch first. Default: the GPU build (PyPI's Linux torch wheels bundle CUDA; the host only needs an NVIDIA driver).
# For a machine with no NVIDIA GPU, build the CPU-only wheel instead and run with TTP_API_DEVICE=cpu:
#   docker build --build-arg TORCH_INDEX=https://download.pytorch.org/whl/cpu ...
# Keep TORCH_VERSION equal to the torch pin in requirements-api.txt.
ARG TORCH_VERSION=2.14.1
ARG TORCH_INDEX=https://pypi.org/simple
RUN pip install --index-url "${TORCH_INDEX}" "torch==${TORCH_VERSION}"

COPY requirements-api.txt .
RUN pip install -r requirements-api.txt
RUN python -m nltk.downloader -d /usr/local/share/nltk_data punkt_tab

COPY ttp_extraction ./ttp_extraction
COPY ttp_api ./ttp_api
COPY data ./data
COPY artifacts ./artifacts

RUN useradd --create-home --uid 10001 ttp
USER ttp

ENV TTP_API_BUNDLE_DIR=/models/ttp-v3 TTP_API_DEVICE=cuda TTP_API_JOB_STORE=memory
EXPOSE 8001
HEALTHCHECK --interval=15s --timeout=5s --start-period=180s --retries=5 \
  CMD ["python", "-c", "import urllib.request as u; u.urlopen('http://127.0.0.1:8001/api/v1/health', timeout=4)"]
CMD ["uvicorn", "ttp_api.main:app", "--host", "0.0.0.0", "--port", "8001"]
