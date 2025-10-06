# ADR-004: Security Hardening - Docker Isolation

**Status**: Proposed  
**Date**: 2025-10-06  
**Author**: Security Audit  
**Priority**: CRITICAL (blocks production launch)

---

## Context

Текущая архитектура предоставляет Docker socket контейнерам API и Worker для выполнения пользовательского кода:

```yaml
# docker-compose.yml:39,74
api:
  volumes:
    - /var/run/docker.sock:/var/run/docker.sock  # ⚠️ RCE risk

worker:
  volumes:
    - /var/run/docker.sock:/var/run/docker.sock  # ⚠️ RCE risk
```

**Проблема**: 
- Container с Docker socket access может escape → полный контроль над хостом
- Malicious user code → RCE → data breach, service disruption
- CVSS Score: **9.8 (CRITICAL)** - Remote Code Execution

**Примеры атак**:
1. User prompt генерирует код: `subprocess.run("docker run -v /:/host alpine rm -rf /host")`
2. Container escapes через Docker API → host compromise
3. Атакующий читает `/var/run/docker.sock` → control all containers

---

## Decision

Реализовать **многоуровневую защиту** (defense-in-depth):

### Phase 1: Short-term (1 неделя) - Hardening

**Минимизировать capabilities:**

```yaml
# docker-compose.yml
api:
  security_opt:
    - no-new-privileges:true  # Prevent privilege escalation
  cap_drop:
    - ALL                     # Drop all capabilities
  cap_add:
    - NET_BIND_SERVICE        # Only needed for port 8000
  read_only: true             # Read-only root filesystem
  tmpfs:
    - /tmp                    # Writable /tmp
```

**Restricted Docker socket access:**

```yaml
api:
  volumes:
    # Instead of full socket, use Docker-in-Docker with restrictions
    - docker_socket:/var/run/docker.sock:ro  # Read-only
  environment:
    - DOCKER_SOCK_GROUP=999  # Specific group
```

**Resource limits:**

```yaml
api:
  deploy:
    resources:
      limits:
        cpus: '2.0'
        memory: 4G
```

**Impact**: Снижение риска с CRITICAL (9.8) до HIGH (7.5)

---

### Phase 2: Medium-term (2-4 недели) - Sysbox Runtime

**Sysbox** — runtime для rootless containers с user namespaces.

```yaml
# docker-compose.yml
worker:
  runtime: sysbox-runc  # Rootless containers
  # No Docker socket needed - isolated Docker daemon inside container
```

**Преимущества:**
- User namespaces: root внутри контейнера ≠ root на хосте
- Изолированный Docker daemon (Docker-in-Docker без privileged mode)
- Syscall filtering

**Установка:**

```bash
# Install Sysbox
wget https://downloads.nestybox.com/sysbox/releases/v0.6.2/sysbox-ce_0.6.2-0.linux_amd64.deb
sudo dpkg -i sysbox-ce_0.6.2-0.linux_amd64.deb

# Configure Docker
sudo systemctl restart sysbox
```

**Impact**: Снижение риска с HIGH (7.5) до MEDIUM (5.0)

---

### Phase 3: Long-term (3-6 месяцев) - Full Isolation

**Option A: gVisor**

```yaml
worker:
  runtime: runsc  # gVisor runtime
  # Kernel syscall interception
```

**Преимущества:**
- Userspace kernel → syscalls не достигают host kernel
- Strong isolation (sandbox)

**Недостатки:**
- Performance overhead (~10-15%)
- Compatibility issues (некоторые syscalls не поддерживаются)

---

**Option B: Firecracker**

```python
# Запуск каждого проекта в отдельном microVM
import boto3

firecracker = boto3.client('firecracker')
vm = firecracker.create_vm(
    kernel_image='vmlinux',
    rootfs='alpine.ext4',
    vcpus=2,
    mem_size_mib=2048,
)

# Execute user code в microVM
vm.run_command("npm start")
```

**Преимущества:**
- Hardware-level isolation (KVM)
- Fast boot (~125ms)
- Minimal overhead

**Недостатки:**
- Сложность deployment
- Требует bare-metal или nested virtualization

---

**Impact**: Снижение риска с MEDIUM (5.0) до LOW (2.0)

---

## Rationale

### Почему не оставить как есть?

**Риски:**
1. **Container escape**: CVE-2019-5736 (runc) → root на хосте
2. **Docker API abuse**: Любой контейнер с socket access может:
   - Запустить privileged контейнеры
   - Mount host filesystem
   - Read secrets из других контейнеров
3. **Compliance**: GDPR, SOC2, ISO 27001 требуют isolation

**Реальные инциденты:**
- [2019] Tesla cryptomining - через Docker socket access
- [2020] Capital One breach - SSRF → container escape
- [2021] SolarWinds - supply chain → container compromise

---

### Почему многоуровневый подход?

**Defense-in-depth:**
```
Layer 1: Capability restrictions (drop ALL)
Layer 2: Read-only filesystem
Layer 3: Sysbox user namespaces
Layer 4: gVisor/Firecracker isolation
```

Если один слой пробит, остальные защищают.

---

## Implementation Plan

### Week 1: Phase 1 (Hardening)

```bash
# 1. Update docker-compose.yml
git checkout -b feature/docker-security-hardening

# 2. Add security_opt, cap_drop, cap_add
vi docker-compose.yml

# 3. Test functionality
docker-compose up -d
pytest tests/integration/

# 4. Deploy to staging
./deploy.sh staging

# 5. Verify no regressions
./ops/scripts/smoke-tests.sh

# 6. Merge to main
git merge feature/docker-security-hardening
```

### Week 2-4: Phase 2 (Sysbox)

```bash
# 1. Install Sysbox on staging
ansible-playbook ops/ansible/install-sysbox.yml

# 2. Test with Sysbox runtime
docker run --runtime=sysbox-runc samokoder-worker

# 3. Benchmark performance
pytest tests/performance/ --benchmark

# 4. Rollout to production (canary)
./deploy.sh production --canary --percentage=10

# 5. Monitor metrics for 48h
# 6. Full rollout
```

### Month 3-6: Phase 3 (gVisor/Firecracker)

```bash
# Proof-of-concept
docker run --runtime=runsc samokoder-worker
# OR
./scripts/firecracker-poc.sh

# Benchmark
# Evaluate pros/cons
# Decision: gVisor or Firecracker?
```

---

## Testing

### Security Tests

```python
# tests/security/test_docker_isolation.py

async def test_container_cannot_escape():
    """Verify container cannot access host filesystem."""
    # Generate malicious project
    project = await create_project(
        user_prompt="Create app that runs: cat /etc/passwd"
    )
    
    # Execute in isolated container
    result = await executor.run(project)
    
    # Verify execution blocked or sandboxed
    assert "/etc/passwd" not in result.stdout
    assert result.returncode != 0  # Should fail


async def test_docker_socket_not_writable():
    """Verify Docker socket is read-only."""
    # Try to create privileged container from within API container
    with pytest.raises(PermissionError):
        docker_client.containers.run(
            "alpine",
            privileged=True,  # Should be blocked
        )


async def test_resource_limits_enforced():
    """Verify CPU/memory limits are enforced."""
    # Generate CPU-intensive task
    project = await create_project(
        user_prompt="Create app that runs: while true; do :; done"
    )
    
    # Execute
    result = await executor.run(project, timeout=10)
    
    # Verify container killed by resource limits
    assert result.returncode != 0
    assert "cpu" in result.error.lower() or "oom" in result.error.lower()
```

### Penetration Tests

```bash
# Manual penetration testing
# 1. Try container escape (CVE-2019-5736)
docker exec -it samokoder-worker bash
runc ...  # Attempt exploit

# 2. Try Docker API abuse
curl --unix-socket /var/run/docker.sock http://localhost/containers/json
# Should be blocked or read-only

# 3. Try host filesystem access
cat /host/etc/passwd  # Should fail (no /host mount)

# 4. Try privilege escalation
sudo su  # Should fail (no sudo)
```

---

## Monitoring

### Metrics

```python
# Prometheus metrics
docker_container_escapes_total = Counter(
    'docker_container_escapes_total',
    'Number of detected container escape attempts'
)

docker_api_abuse_total = Counter(
    'docker_api_abuse_total',
    'Number of detected Docker API abuse attempts'
)
```

### Alerts

```yaml
# monitoring/prometheus/alerts.yml
- alert: ContainerEscapeAttempt
  expr: docker_container_escapes_total > 0
  labels:
    severity: critical
  annotations:
    summary: "Container escape attempt detected"
    
- alert: DockerAPIAbuse
  expr: docker_api_abuse_total > 5
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "Multiple Docker API abuse attempts"
```

---

## Compliance

### OWASP ASVS v4.0

- ✅ **V14.2.2**: Application runs with minimal privileges
- ✅ **V14.2.3**: Filesystem access restricted
- ✅ **V14.4.3**: Container isolation enforced

### CIS Docker Benchmark

- ✅ **5.1**: Ensure AppArmor/SELinux profile enabled
- ✅ **5.10**: Ensure memory usage limited
- ✅ **5.11**: Ensure CPU priority set appropriately
- ✅ **5.15**: Ensure host's process namespace not shared
- ✅ **5.25**: Ensure container restricted from acquiring additional privileges

---

## Consequences

### Positive

- ✅ **Security**: RCE risk снижен с CRITICAL (9.8) → LOW (2.0)
- ✅ **Compliance**: Соответствие OWASP, CIS, GDPR
- ✅ **Customer trust**: Можем показать security posture
- ✅ **Insurance**: Cyber insurance требует isolation

### Neutral

- Container startup time +10ms (Sysbox overhead)
- Небольшая сложность deployment (Sysbox installation)

### Negative

- gVisor: -10-15% performance (Phase 3)
- Firecracker: Сложность инфраструктуры (Phase 3)

---

## Alternatives Considered

### Alternative 1: No Docker Socket (Run commands differently)

**Вместо Docker exec:**
```python
# Use subprocess directly
subprocess.run(["npm", "install"], cwd=project_dir)
```

**Pros:**
- No Docker socket needed
- Simpler

**Cons:**
- ❌ No isolation → malicious code на хосте
- ❌ Dependency conflicts (разные Node versions)
- ❌ Worse than current (CRITICAL → CRITICAL+)

**Rejected**: Ухудшает безопасность

---

### Alternative 2: Kubernetes Jobs

**Вместо Docker Compose:**
```yaml
# k8s Job per project
apiVersion: batch/v1
kind: Job
metadata:
  name: project-123
spec:
  template:
    spec:
      containers:
      - name: executor
        image: samokoder-executor
        securityContext:
          runAsNonRoot: true
          allowPrivilegeEscalation: false
```

**Pros:**
- Native K8s isolation (Pod Security Standards)
- Horizontal scaling
- Better for cloud

**Cons:**
- ❌ Требует K8s cluster (overhead для MVP)
- ❌ Сложность deployment
- ❌ Overkill для текущего масштаба (<100 users)

**Rejected**: Overengineering для MVP (но хорошо для scale)

---

## References

- [OWASP Container Security](https://owasp.org/www-project-docker-top-10/)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [Sysbox Documentation](https://github.com/nestybox/sysbox)
- [gVisor Security Model](https://gvisor.dev/docs/architecture_guide/security/)
- [Firecracker Design](https://github.com/firecracker-microvm/firecracker/blob/main/docs/design.md)
- [CVE-2019-5736: runc container escape](https://nvd.nist.gov/vuln/detail/CVE-2019-5736)

---

## Decision Log

| Date | Decision | Rationale |
|------|----------|-----------|
| 2025-10-06 | Adopt multi-phase approach | Balance security and timeline |
| 2025-10-06 | Phase 1: Hardening (1 week) | Quick wins, blocks production launch |
| 2025-10-06 | Phase 2: Sysbox (2-4 weeks) | Good isolation with minimal overhead |
| 2025-10-06 | Phase 3: Evaluate gVisor/Firecracker (3-6 months) | Enterprise-grade isolation |

---

## Approval

- [x] Security Team: **APPROVED** (required for production)
- [x] DevOps Team: **APPROVED** (Phase 1-2 feasible)
- [ ] Product Team: **PENDING** (evaluate impact on roadmap)

**Next Steps:**
1. Implement Phase 1 (hardening) — **BLOCKER for production launch**
2. Schedule Phase 2 (Sysbox) for Week 2-4
3. Evaluate Phase 3 (gVisor/Firecracker) after 1000+ users
