import http from 'k6/http';
import { check } from 'k6';

// The benchmark sends requests that intentionally return 404 (backend has no
// /api/v1/test route) or 401/403/400 for policy failures. Treat these as
// successful HTTP transactions so http_req_failed reflects only network errors.
http.setResponseCallback(http.expectedStatuses(200, 404, 401, 403, 400));

const url = __ENV.URL || 'http://localhost/api/v1/test';
const rate = parseInt(__ENV.RATE || '500', 10);
const duration = __ENV.DURATION || '30s';

const headers = {
  'Content-Type': 'application/json',
};
if (__ENV.KEY) {
  headers['X-Api-Key'] = __ENV.KEY;
}

const payload = JSON.stringify({ name: 'hello' });

export const options = {
  scenarios: {
    constant_load: {
      executor: 'constant-arrival-rate',
      rate: rate,
      timeUnit: '1s',
      duration: duration,
      preAllocatedVUs: 100,
      maxVUs: 250,
    },
  },
};

export default function () {
  const res = http.post(url, payload, { headers, timeout: '120s' });
  check(res, {
    'status is 404 or 401/403/400': (r) =>
      r.status === 404 || r.status === 401 || r.status === 403 || r.status === 400,
    'no connection errors': (r) => r.error === '',
  });
}
