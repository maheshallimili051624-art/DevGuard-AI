import time
from collections import defaultdict
from fastapi import Request, HTTPException
from app.config import RATE_LIMIT_PER_MINUTE


class SlidingWindowRateLimiter:
    def __init__(self, limit_per_minute: int = 30):
        self.limit = limit_per_minute
        self.requests = defaultdict(list)

    def check(self, request: Request, custom_limit: int = None):
        client_ip = request.headers.get("x-forwarded-for")
        if client_ip:
            client_ip = client_ip.split(",")[0].strip()
        else:
            client_ip = request.client.host if request.client else "unknown"

        now = time.time()
        window_start = now - 60.0
        limit = custom_limit or self.limit

        # Clean older timestamps
        self.requests[client_ip] = [ts for ts in self.requests[client_ip] if ts > window_start]

        if len(self.requests[client_ip]) >= limit:
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded ({limit} requests/minute). Please wait before submitting more requests."
            )

        self.requests[client_ip].append(now)


limiter = SlidingWindowRateLimiter(limit_per_minute=RATE_LIMIT_PER_MINUTE)
