from time import perf_counter
from telemetry.adapters import normalize
from datetime import datetime, timezone

for size in (100, 1000, 10000):
    started = perf_counter()
    for index in range(size): normalize({"event_type":"heartbeat","timestamp":datetime.now(timezone.utc).isoformat(),"event_id":str(index)}, "benchmark", "performance")
    elapsed = perf_counter() - started
    print({"events": size, "throughput_per_sec": round(size / elapsed, 2), "latency_ms": round(elapsed * 1000 / size, 4), "processing_ms": round(elapsed * 1000, 3)})
