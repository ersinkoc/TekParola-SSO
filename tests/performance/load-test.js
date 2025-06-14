import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');
const loginDuration = new Trend('login_duration');
const profileDuration = new Trend('profile_duration');

// Test configuration
export const options = {
  stages: [
    { duration: '30s', target: 10 },   // Ramp up to 10 users
    { duration: '1m', target: 50 },    // Ramp up to 50 users
    { duration: '3m', target: 100 },   // Stay at 100 users
    { duration: '1m', target: 50 },    // Ramp down to 50 users
    { duration: '30s', target: 0 },    // Ramp down to 0 users
  ],
  thresholds: {
    http_req_duration: ['p(95)<500', 'p(99)<1000'], // 95% of requests under 500ms
    errors: ['rate<0.05'],                           // Error rate under 5%
    login_duration: ['p(95)<1000'],                  // 95% of logins under 1s
    profile_duration: ['p(95)<300'],                 // 95% of profile requests under 300ms
  },
};

const BASE_URL = __ENV.BASE_URL || 'https://staging.tekparola.com';

function randomEmail() {
  return `user_${Math.random().toString(36).substring(7)}@test.com`;
}

export default function () {
  const email = randomEmail();
  const password = 'TestPass123!';

  // Register user
  const registerRes = http.post(
    `${BASE_URL}/api/v1/auth/register`,
    JSON.stringify({
      email,
      firstName: 'Load',
      lastName: 'Test',
      password,
    }),
    {
      headers: { 'Content-Type': 'application/json' },
    }
  );

  check(registerRes, {
    'register successful': (r) => r.status === 201,
  });
  errorRate.add(registerRes.status !== 201);

  sleep(1);

  // Login
  const loginStart = Date.now();
  const loginRes = http.post(
    `${BASE_URL}/api/v1/auth/login`,
    JSON.stringify({ email, password }),
    {
      headers: { 'Content-Type': 'application/json' },
    }
  );
  loginDuration.add(Date.now() - loginStart);

  const loginSuccess = check(loginRes, {
    'login successful': (r) => r.status === 200,
    'has access token': (r) => r.json('data.tokens.accessToken') !== undefined,
  });
  errorRate.add(!loginSuccess);

  if (!loginSuccess) {
    return;
  }

  const authToken = loginRes.json('data.tokens.accessToken');
  const authHeaders = {
    'Content-Type': 'application/json',
    Authorization: `Bearer ${authToken}`,
  };

  sleep(1);

  // Get profile
  const profileStart = Date.now();
  const profileRes = http.get(`${BASE_URL}/api/v1/auth/profile`, {
    headers: authHeaders,
  });
  profileDuration.add(Date.now() - profileStart);

  check(profileRes, {
    'profile retrieved': (r) => r.status === 200,
    'has user data': (r) => r.json('data.user.email') === email,
  });
  errorRate.add(profileRes.status !== 200);

  sleep(1);

  // Search users
  const searchRes = http.get(
    `${BASE_URL}/api/v1/users/search?search=test&page=1&limit=10`,
    {
      headers: authHeaders,
    }
  );

  check(searchRes, {
    'search successful': (r) => r.status === 200,
  });
  errorRate.add(searchRes.status !== 200);

  sleep(1);

  // Get roles
  const rolesRes = http.get(`${BASE_URL}/api/v1/roles`, {
    headers: authHeaders,
  });

  check(rolesRes, {
    'roles retrieved': (r) => r.status === 200,
  });
  errorRate.add(rolesRes.status !== 200);

  sleep(1);

  // Refresh token
  const refreshToken = loginRes.json('data.tokens.refreshToken');
  const refreshRes = http.post(
    `${BASE_URL}/api/v1/auth/refresh-token`,
    JSON.stringify({ refreshToken }),
    {
      headers: { 'Content-Type': 'application/json' },
    }
  );

  check(refreshRes, {
    'refresh successful': (r) => r.status === 200,
    'has new tokens': (r) => r.json('data.tokens.accessToken') !== undefined,
  });
  errorRate.add(refreshRes.status !== 200);

  sleep(1);

  // Logout
  const logoutRes = http.post(
    `${BASE_URL}/api/v1/auth/logout`,
    null,
    {
      headers: authHeaders,
    }
  );

  check(logoutRes, {
    'logout successful': (r) => r.status === 200,
  });
  errorRate.add(logoutRes.status !== 200);

  sleep(2);
}

export function handleSummary(data) {
  return {
    'performance-report.json': JSON.stringify(data),
    stdout: textSummary(data, { indent: ' ', enableColors: true }),
  };
}
