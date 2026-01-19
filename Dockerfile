FROM python:3.9-slim

# Install system dependencies for C development and libclang
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    clang \
    libclang-dev \
    ccls \
    make \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy project files
COPY zscope/zscope/ /app/zscope/
COPY zscope/pyproject.toml /app/
COPY zscope/setup.py /app/
COPY zscope/README.md /app/
COPY zscope/tests/ /app/tests/

# Install Python dependencies
RUN pip install --no-cache-dir -e .[dev]

# Copy test C project
COPY test_c_project/ /app/test_c_project/

# Copy multi-file test project
COPY test_c_project_multi/ /app/test_c_project_multi/

# Copy cache module test case
COPY zscope/tests/cache_module/ /app/zscope/tests/cache_module/

# Copy verification script
COPY verify_linux.sh /app/

# Make verification script executable
RUN chmod +x /app/verify_linux.sh

# Set environment variables (can be overridden)
ENV PYTHONUNBUFFERED=1

# Default command
CMD ["/bin/bash"]
