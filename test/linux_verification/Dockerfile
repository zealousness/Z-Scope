FROM python:3.9-slim

# Install clangd, git, and build tools
RUN apt-get update && apt-get install -y \
    clangd \
    git \
    gcc \
    make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 1. Setup the project package
COPY zscope /app/zscope_pkg
RUN pip install -e /app/zscope_pkg

# 2. Setup the target project at the path expected by compile_commands.json
RUN mkdir -p /app/zscope/tests/cache_module
COPY test/cache_module /app/zscope/tests/cache_module

# 3. Setup verification control files
COPY test/linux_verification/run_test.py /app/run_test.py
COPY test/linux_verification/zscope_linux.yaml /app/zscope/tests/cache_module/zscope_linux.yaml

# Set environment variables
ENV PYTHONPATH=/app/zscope_pkg
WORKDIR /app/zscope/tests/cache_module

# Run the verification script (unbuffered)
CMD ["python", "-u", "/app/run_test.py"]
