import http from "k6/http";
import { check, sleep } from "k6";

const BASE_URL = __ENV.BASE_URL || "http://localhost:8080";
const TOKEN = __ENV.TOKEN || "";
const VUS = Number(__ENV.K6_VUS || 100);
const DURATION = __ENV.K6_DURATION || "5m";

export const options = {
  scenarios: {
    mixed: {
      executor: "constant-vus",
      vus: VUS,
      duration: DURATION,
    },
  },
  thresholds: {
    http_req_duration: ["p(95)<100"],
    http_req_failed: ["rate<0.001"],
  },
};

function authHeaders() {
  const headers = { "Content-Type": "application/json" };
  if (TOKEN) {
    headers.Authorization = `Bearer ${TOKEN}`;
  }
  return headers;
}

export default function () {
  const n = Math.random();

  if (n < 0.6) {
    const res = http.get(`${BASE_URL}/api/v1/rules/?page=1&page_size=20`, {
      headers: authHeaders(),
      responseCallback: http.expectedStatuses(200),
    });
    check(res, { "rules list status 200": (r) => r.status === 200 });
  } else if (n < 0.9) {
    const payload = JSON.stringify({
      name: `k6-rule-${__VU}-${__ITER}`,
      mode: "single",
      ingress_node_id: __ENV.NODE_ID || "",
      target_host: "example.com",
      target_port: 443,
    });
    const res = http.post(`${BASE_URL}/api/v1/rules/`, payload, {
      headers: authHeaders(),
      responseCallback: http.expectedStatuses({ min: 200, max: 499 }),
    });
    check(res, { "rule create status 200/4xx": (r) => r.status >= 200 && r.status < 500 });
  } else {
    const res = http.get(`${BASE_URL}/api/v1/events`, {
      headers: authHeaders(),
      timeout: "5s",
      responseCallback: http.expectedStatuses(200, 401),
    });
    check(res, { "sse status 200/401": (r) => r.status === 200 || r.status === 401 });
  }

  sleep(1);
}
