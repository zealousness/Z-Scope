"""Real HTTP/DB/owner request-race probe; only scanner and pause are controlled."""
import concurrent.futures
import hashlib
import http.server
import json
import os
from pathlib import Path
import sys
import threading
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen

assert sys.platform == "linux"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
sys.path.insert(0, str(ROOT / "tests"))
from test_config_v2 import _config, _write
from zscope.orchestration.jobs.service import ScanJobService
from zscope.web import server
from zscope.web.scan_jobs_service import ScanJobsHttpService
from zscope.web.services import ReportFeedbackService

OUT = HERE / "review-repro/job-request-atomicity"
OUT.mkdir(parents=True, exist_ok=True)
project = OUT / "project"
project.mkdir()
(project / "unit.c").write_text("int main(void) { return 0; }\n")
config = _write(project, _config(project))
scanner = OUT / "scanner.py"
counter = OUT / "scanner-count.txt"
scanner.write_text("import sys\nfrom pathlib import Path\nfrom zscope.reporting.json_io import write_report_atomic\nwith Path(sys.argv[2]).open('a') as f: f.write('scanner\\n')\nwrite_report_atomic(Path(sys.argv[1])/'report.json', {'schema_version':2,'issues':[],'completeness':'complete','metadata':{'synthetic_only':True}})\n")
paused = threading.Event()
release = threading.Event()
guard = threading.Lock()

class PauseAfterOwnerStarts(ScanJobService):
    first = True

    def _record_request(self, *args, **kwargs):
        with guard:
            hold = self.first and kwargs["endpoint"] == "start"
            if hold:
                self.first = False
        if hold:
            paused.set()
            if not release.wait(40):
                raise RuntimeError("probe release timeout")
        return super()._record_request(*args, **kwargs)

os.environ["PYTHONPATH"] = str(ROOT)
engine = PauseAfterOwnerStarts(config, scan_command_builder=lambda path, depth, exe: [exe, str(scanner), str(project), str(counter)])
feedback = ReportFeedbackService(report_filename=str(project / "report.json"))
server._scan_jobs_http_service = ScanJobsHttpService(config, feedback, engine=engine)
httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), server.ZScopeHandler)
thread = threading.Thread(target=httpd.serve_forever, daemon=True)
thread.start()

def call(path, payload=None):
    request = Request(f"http://127.0.0.1:{httpd.server_port}" + path,
                      data=json.dumps(payload).encode() if payload is not None else None,
                      headers={"Content-Type": "application/json"})
    try:
        response = urlopen(request, timeout=45)
    except HTTPError as response_error:
        return response_error.code, json.loads(response_error.read())
    with response:
        return response.status, json.loads(response.read())

try:
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        first = pool.submit(call, "/api/jobs", {"request_id": "same-create-key"})
        assert paused.wait(15)
        stop = time.monotonic() + 20
        while time.monotonic() < stop:
            jobs = call("/api/jobs")[1]["jobs"]
            if jobs and jobs[0]["status"] == "completed":
                break
            time.sleep(.1)
        assert jobs[0]["status"] == "completed", jobs
        duplicate = call("/api/jobs", {"request_id": "same-create-key"})
        release.set()
        original = first.result(timeout=10)
        stop = time.monotonic() + 20
        while time.monotonic() < stop:
            jobs = call("/api/jobs")[1]["jobs"]
            if all(job["status"] == "completed" for job in jobs):
                break
            time.sleep(.1)
        proof = {"synthetic_scanner_only": True, "real_http_sqlite_detached_owner": True,
                 "fault_injection": "pause first handler before request registration; let its actual owner finish",
                 "first_response": original, "same_key_second_response": duplicate,
                 "job_ids": [job["job_id"] for job in jobs],
                 "statuses": [job["status"] for job in jobs],
                 "scanner_invocations": len(counter.read_text().splitlines()),
                 "service_sha256": hashlib.sha256((ROOT / "zscope/orchestration/jobs/service.py").read_bytes()).hexdigest()}
        (OUT / "review.json").write_text(json.dumps(proof, indent=2) + "\n")
        print(json.dumps(proof), flush=True)
finally:
    release.set()
    httpd.shutdown()
    httpd.server_close()
    thread.join(timeout=5)
