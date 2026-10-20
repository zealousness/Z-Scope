"""PROPOSAL ONLY: stage the approved manifest after explicit implementation approval."""
import hashlib, json, pathlib, shutil, sys
manifest = json.loads(pathlib.Path(sys.argv[1]).read_text())
target = pathlib.Path(sys.argv[2]).resolve()
assert not target.exists(), 'Use a fresh context; do not overwrite old files'
for item in manifest['files'].values():
    source = pathlib.Path(item['source'])
    assert hashlib.sha256(source.read_bytes()).hexdigest() == item['sha256'], str(source)
target.mkdir(parents=True)
for item in manifest['files'].values():
    source = pathlib.Path(item['source'])
    destination = target / 'rootfs' / item['destination']
    assert destination.resolve().is_relative_to(target)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(item['mode'])
    assert hashlib.sha256(destination.read_bytes()).hexdigest() == item['sha256']
for name in ('clang', 'llvm-symbolizer'):
    wrapper = target / 'rootfs/usr/bin' / name
    wrapper.parent.mkdir(parents=True, exist_ok=True)
    wrapper.write_text('#!/bin/sh\nexport LD_LIBRARY_PATH=/opt/v02-host-libs:/usr/lib/llvm-18/lib\nexec /usr/lib/llvm-18/bin/' + name + ' "$@"\n', encoding='utf-8')
    wrapper.chmod(0o755)
containerfile = pathlib.Path(__file__).with_name('Containerfile.clang18.proposed')
shutil.copyfile(containerfile, target / 'Containerfile')
print(json.dumps({'context':str(target), 'files':manifest['file_count'], 'tool_bytes':manifest['total_file_bytes'], 'image_built':False}))
