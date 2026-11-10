#!/bin/sh
# Resolve the installed launcher, including symlinks, without changing caller cwd.
set -eu
invoked=$(basename -- "$0")
link_target=$0
while [ -L "$link_target" ]; do
    next_target=$(readlink -- "$link_target")
    case "$next_target" in
        /*) link_target=$next_target ;;
        *) link_target="$(dirname -- "$link_target")/$next_target" ;;
    esac
    candidate=$(basename -- "$link_target")
    if [ "$candidate" != zscope-launch ]; then
        invoked=$candidate
    fi
done
launcher=$(readlink -f -- "$0")
bundle=$(dirname -- "$(dirname -- "$launcher")")
export Z_SCOPE_BUNDLE_ROOT="$bundle"
export PYTHONHOME="$bundle/runtime/python"
export PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1
unset PYTHONPATH PYTHONUSERBASE
export PATH="$bundle/bin:${PATH:-/usr/bin:/bin}"
export LD_LIBRARY_PATH="$bundle/lib"
export SSL_CERT_FILE="${SSL_CERT_FILE:-$bundle/share/cacert.pem}"
export REQUESTS_CA_BUNDLE="${REQUESTS_CA_BUNDLE:-$SSL_CERT_FILE}"
export GIT_SSL_CAINFO="${GIT_SSL_CAINFO:-$SSL_CERT_FILE}"
export GIT_EXEC_PATH="$bundle/tools/git/libexec/git-core"
export GIT_TEMPLATE_DIR="$bundle/tools/git/share/git-core/templates"
if [ -d "$bundle/tools/llvm18" ]; then
    export LLVM_COMPILER=clang
    export LLVM_COMPILER_PATH=""
    export LLVM_CC_NAME="$bundle/bin/clang-18"
    export LLVM_CXX_NAME="$bundle/bin/clang++-18"
    export LLVM_LINK_NAME="$bundle/bin/llvm-link"
    export LLVM_AR_NAME="$bundle/bin/llvm-ar"
    export LLVM_NM_NAME="$bundle/bin/llvm-nm"
    export LLVM_OBJCOPY_NAME="$bundle/bin/llvm-objcopy"
    export GLLVM_OBJCOPY="$bundle/bin/llvm-objcopy"
    export SVF_DIR="$bundle/tools/svf"
fi
if [ -d "$bundle/tools/jdk" ]; then
    export JAVA_HOME="$bundle/tools/jdk"
fi
exec "$bundle/runtime/python/bin/python3.13" -s "$bundle/libexec/dispatch.py" "$invoked" "$@"
