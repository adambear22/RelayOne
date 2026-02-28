# Playwright E2E Scenarios (Reference)

## Scenario 1: Complete Node Deployment Wizard
- Login as a normal user and open `/nodes`.
- Click `添加节点`, finish Step 1, and submit.
- In Step 2 copy/run install command (mock callback), click `我已执行，等待连接`.
- Verify Step 3 timeline updates via `deploy.progress` SSE and reaches `progress=100`.
- Assert node status badge changes to `在线` without manual refresh.

## Scenario 2: Rule Layer2 Parameters + URL Preview
- Open rule create drawer and select a valid ingress node.
- Expand advanced/expert sections and set non-default NodePass params.
- Assert URL preview changes in real time.
- Submit creation request and verify payload/query params match preview values.

## Scenario 3: Quota Exceeded -> SSE -> Rule Auto Paused
- Prepare user traffic close to quota and one running rule.
- Simulate traffic report that exceeds quota.
- Assert `traffic.update` SSE event is received by frontend.
- Assert running rule badge changes to `paused` automatically.

## Scenario 4: Benefit Code Redeem -> VIP + Quota Update
- Login user and open code redeem entry.
- Redeem a valid benefit code.
- Assert success toast/message appears.
- Verify VIP level, expiry, and quota cards update from API/SSE without full page reload.
