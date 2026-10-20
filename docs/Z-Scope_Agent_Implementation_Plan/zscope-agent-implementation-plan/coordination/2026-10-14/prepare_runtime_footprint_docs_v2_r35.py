"""Add the reviewed prewrite obligations to immutable module document drafts."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
OLD = ROOT / 'artifacts/runtime-footprint-module-docs-r35-20261017'
OUT = OLD / 'revision-2'
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
if sys.platform != 'linux' or sys.flags.optimize:
    raise RuntimeError('Unoptimized Linux required')
names = ('retrieval-backends.md', 'execution-orchestration.md', 'configuration-state.md')
expected = ('c9c1869d8d2c9440f04bf1db2431b90be1916df1762ed65ab55ee95b13650775',
    'e156433e7b25ccbbb18a0d5597d83a6e63da54cc9b4091fa065bda151de132da',
    'e30e9fc47cb58929e66522ff8cc90fdfcd6f5b7cfda0732d499bd71719f9200f')
assert all(sha(OLD / name) == digest for name, digest in zip(names, expected))
additions = {
    'retrieval-backends.md': '运行产物的物理输入保护集合覆盖同一索引全部实际编译上下文读取的源码、头文件和查找候选，不能仅收集当前入口 plan 的依赖；入口语义权限仍只属于该 plan 的精确实例。一个未选 TU 实际读入的文件不能因当前入口未读取它而变成可覆盖产物。签发和消费还须核对当前工具字节、实际加载依赖及已使用的标准安装来源；仅检查编译数据库、mtime 或普通 context 状态不足以授权第一次可能创建 SQLite sidecar 的连接。',
    'execution-orchestration.md': '批量报告备份按本次实际时间计算精确目标，并在写入前由同一索引工厂核对和登记。符号链接或硬链接指向实际编译输入的备份目标必须拒绝；检查与实际发布使用同一受限作业绑定和文件身份，不把整个 backups 子树作为可写例外。工具输入已失效时，纯文件核验须在第一次 Store 连接之前拒绝，不能先创建 WAL/SHM 等产物再由后续语义检查补救。',
}
if OUT.exists():
    raise RuntimeError('Preserve previous draft')
OUT.mkdir()
for name in names:
    text = (OLD / name).read_text(encoding='utf-8').rstrip() + '\n'
    if name in additions:
        text += '\n' + additions[name] + '\n'
    (OUT / name).write_text(text, encoding='utf-8', newline='\n')
record = dict(actual_task='/root', prepared_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(),
    status='draft_pending_final_implementation_and_actual_probe_review',
    draft_sources_sha256={name: sha(OUT / name) for name in names},
    preserved_previous_drafts_sha256={str(OLD / name): digest for name, digest in zip(names, expected)},
    reference_sha256={str(ROOT / 'artifacts/job-runtime-footprint-source-review-r34-20261017/third-tu-protection-source-risk-review.json'): 'ea782541d4e5552c108b04fa0d3544d5f42ec255a638e0cc5c8dc3c6bd2e18fb'},
    candidate_product_written=False, stage_intake=False, root_intake=False, whole_package_acceptance=False)
(OUT / 'preparation.json').write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8', newline='\n')
print(json.dumps(dict(prepared_at=record['prepared_at'], status=record['status'], sources=record['draft_sources_sha256'])))
