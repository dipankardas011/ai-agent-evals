# Ai Agent Evals

![](./assets/ai-agent-evals.webp)

Goal: able to test your AI performance withrespect to the task in hand and see how much it scores.

It takes instruction.md with artifacts to work with inside a container where the Ai Agent has access to the terminal where it performs the operation and once its done we evaluate aka verify its work and score them.

## Setup

```shell
uv sync -p 3.12
source .venv/bin/activate
```

To test the evaulation logic
```shell
harbor run -p "./<test>" --agent oracle
```

For running on different models
for claude models
```
ANTHROPIC_API_KEY=x ANTHROPIC_BASE_URL=http://127.0.0.1:3456 harbor run -p "./<test>" --agent terminus-2 --model claude-opus-4-6 -k 1
```

for qwen or any other model
```shell
export OPENAI_API_BASE="http://192.168.1.18:8000/v1"
export OPENAI_API_KEY="local-dummy-key"
harbor run -p "./compromised-prod-server-easy" \
    --agent terminus-2 \
    --model custom_openai/Qwen3.5-9B-Q5_K_M.gguf \
    --ak 'model_info:dict={"max_input_tokens": 131072, "max_output_tokens": 131072}' -k 2
```
> How I got this model for that checkout [my blog](https://dipankar-das.com/blog/i-went-deep-localllm/)

## Tests

### 1. Compromised Prod Server (Hard)


<details>
Best result

```shell
============================================================
TRIAL: compromised-prod-server-hard__8tBwgNY
============================================================
  Agent:     terminus-2
  Task:      dipankardas/compromised-prod-server-hard
  Reward:    0.0 ✗
  environment_setup        0:00:02
  agent_setup              0:00:19
  agent_execution          0:15:00
  verifier                 0:01:23

  Tests: 22/33 passed, 11 failed

    ✗ test_ssh_access                          (0.20s)
    ✗ test_umask_fixed                         (0.01s)
    ✗ test_new_file_permissions                (0.01s)
    ✓ test_ssh_key_permissions                 (0.00s)
    ✓ test_no_rogue_ssh_key                    (0.00s)
    ✗ test_prod_svr_authorized_keys_intact     (0.19s)
    ✗ test_no_backdoor_persistence             (0.00s)
    ✓ test_backdoor_key_stays_removed          (70.01s)
    ✓ test_jumphost_root_ca_in_place           (0.06s)
    ✗ test_nginx_config_valid                  (0.21s)
    ✗ test_ssl_chain_valid                     (0.21s)
    ✗ test_server_cert_is_original             (0.19s)
    ✓ test_healthz_endpoint                    (0.01s)
    ✓ test_basic_auth_required                 (0.01s)
    ✓ test_basic_auth_works                    (0.01s)
    ✓ test_response_contains_name              (0.01s)
    ✓ test_response_is_ascii                   (0.01s)
    ✓ test_response_format                     (0.01s)
    ✓ test_cors_headers                        (0.01s)
    ✗ test_cors_preflight_options              (0.01s)
    ✓ test_security_header_nosniff             (0.01s)
    ✓ test_security_header_frame_options       (0.01s)
    ✓ test_security_header_hsts                (0.01s)
    ✓ test_input_length_limit                  (0.01s)
    ✓ test_input_xss_escaped                   (0.01s)
    ✓ test_input_non_ascii_rejected            (0.03s)
    ✓ test_input_null_byte_rejected            (0.01s)
    ✓ test_method_not_allowed_post             (0.01s)
    ✓ test_method_not_allowed_delete           (0.01s)
    ✓ test_path_traversal_blocked              (0.01s)
    ✓ test_wrong_basic_auth_rejected           (0.01s)
    ✗ test_go_unit_tests_handlers              (0.59s)
    ✗ test_app_not_running_as_root             (0.42s)

  ──────────────────────────────────────────────────
  FAILURE DETAILS
  ──────────────────────────────────────────────────

  ✗ test_ssh_access
    The test failed in the call phase due to an assertion error
    E       AssertionError: SSH failed: Permission denied, please try again.
    E         Permission denied, please try again.
    E         root@prod-svr: Permission denied (publickey,password).
    E       assert 255 == 0
    E        +  where 255 = CompletedProcess(args='ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 prod-svr "echo connection_ok"', returncode...ed, please try again.\nPermission denied, please try again.\nroot@prod-svr: Permission denied (publickey,password).\n').returncode

  ✗ test_umask_fixed
    The test failed in the call phase due to an assertion error
    E       AssertionError: umask is still 0000 — attacker's change not reverted
    E       assert '0000' != '0000'

  ✗ test_new_file_permissions
    The test failed in the call phase due to an assertion error
    E       AssertionError: VULNERABILITY: Newly created files are world-writable (permissions: 666). The malicious umask in the initialization scripts was not properly removed!
    E       assert '666' != '666'

  ✗ test_prod_svr_authorized_keys_intact
    The test failed in the call phase due to an assertion error
    E       AssertionError: Could not read prod-svr authorized_keys: Permission denied, please try again.
    E         Permission denied, please try again.
    E         root@prod-svr: Permission denied (publickey,password).
    E       assert 255 == 0
    E        +  where 255 = CompletedProcess(args='ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 prod-svr "cat /root/.ssh/authorized_keys"'...ed, please try again.\nPermission denied, please try again.\nroot@prod-svr: Permission denied (publickey,password).\n').returncode

  ✗ test_no_backdoor_persistence
    The test failed in the call phase due to an assertion error
    E       AssertionError: Backdoor cron file /etc/cron.d/apt-compat still exists
    E       assert 'gone' in 'exists\n'
    E        +  where 'exists\n' = CompletedProcess(args='test -f /etc/cron.d/apt-compat && echo exists || echo gone', returncode=0, stdout='exists\n', stderr='').stdout

  ✗ test_nginx_config_valid
    The test failed in the call phase due to an assertion error
    E       AssertionError: nginx config test failed:
    E       assert 255 == 0
    E        +  where 255 = CompletedProcess(args='ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 prod-svr "nginx -t 2>&1"', returncode=255,...ed, please try again.\nPermission denied, please try again.\nroot@prod-svr: Permission denied (publickey,password).\n').returncode

  ✗ test_ssl_chain_valid
    The test failed in the call phase due to an assertion error
    E       AssertionError: SSL certificate chain is incomplete — missing intermediate CA. Output:
    E       assert ('depth=1' in '' or 'Intermediate' in '')

  ✗ test_server_cert_is_original
    The test failed in the call phase due to an assertion error
    E       AssertionError: server.crt issuer is not TestIntermediateCA — cert chain was tampered with. Got:
    E       assert 'CN=TestIntermediateCA' in ''

  ✗ test_cors_preflight_options
    The test failed in the call phase due to an assertion error
    E       AssertionError: OPTIONS preflight returned 401
    E       assert 401 == 200
    E        +  where 401 = <Response [401]>.status_code

  ✗ test_go_unit_tests_handlers
    The test failed in the call phase due to an assertion error
    E       AssertionError: Go handler tests failed:
    E       assert 255 == 0
    E        +  where 255 = CompletedProcess(args='ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 prod-svr "cd /app/src && go test -run \'Te...ed, please try again.\nPermission denied, please try again.\nroot@prod-svr: Permission denied (publickey,password).\n').returncode

  ✗ test_app_not_running_as_root
    The test failed in the call phase due to an assertion error
    E       AssertionError: App is not running as appuser
    E       assert '' != ''
    E        +  where '' = <built-in method strip of str object at 0xb3b3f0>()
    E        +    where <built-in method strip of str object at 0xb3b3f0> = ''.strip
    E        +      where '' = CompletedProcess(args='ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 prod-svr "pgrep -u appuser prodserver"', r...ed, please try again.\nPermission denied, please try again.\nroot@prod-svr: Permission denied (publickey,password).\n').stdout
```
</details>

Here is the terminal actions it took
![](./assets/compromised-prod-server-hard-best.gif)


### 2. Compromised Prod Server (Easy)


<details>

Best Results:
```
============================================================
TRIAL: compromised-prod-server-easy__taeage5
============================================================
  Agent:     terminus-2
  Task:      dipankardas/compromised-prod-server-easy
  Reward:    0.0 ✗
  environment_setup        0:00:03
  agent_setup              0:00:53
  agent_execution          0:06:36
  verifier                 0:01:30

  Tests: 26/30 passed, 4 failed

    ✓ test_ssh_access                          (0.22s)
    ✓ test_ssh_key_permissions                 (0.00s)
    ✗ test_no_rogue_ssh_key                    (0.00s)
    ✓ test_prod_svr_authorized_keys_intact     (0.21s)
    ✗ test_no_backdoor_persistence             (0.00s)
    ✗ test_backdoor_key_stays_removed          (70.01s)
    ✓ test_jumphost_root_ca_in_place           (0.07s)
    ✓ test_nginx_config_valid                  (0.29s)
    ✓ test_ssl_chain_valid                     (0.26s)
    ✓ test_healthz_endpoint                    (0.01s)
    ✓ test_basic_auth_required                 (0.01s)
    ✓ test_basic_auth_works                    (0.01s)
    ✓ test_response_contains_name              (0.01s)
    ✓ test_response_is_ascii                   (0.01s)
    ✓ test_response_format                     (0.01s)
    ✓ test_cors_headers                        (0.01s)
    ✓ test_cors_preflight_options              (0.01s)
    ✓ test_security_header_nosniff             (0.01s)
    ✓ test_security_header_frame_options       (0.01s)
    ✓ test_security_header_hsts                (0.01s)
    ✓ test_input_length_limit                  (0.01s)
    ✓ test_input_xss_escaped                   (0.01s)
    ✓ test_input_non_ascii_rejected            (0.04s)
    ✗ test_input_null_byte_rejected            (0.01s)
    ✓ test_method_not_allowed_post             (0.01s)
    ✓ test_method_not_allowed_delete           (0.01s)
    ✓ test_path_traversal_blocked              (0.01s)
    ✓ test_wrong_basic_auth_rejected           (0.01s)
    ✓ test_go_unit_tests_handlers              (2.63s)
    ✓ test_app_not_running_as_root             (0.44s)

  ──────────────────────────────────────────────────
  FAILURE DETAILS
  ──────────────────────────────────────────────────

  ✗ test_no_rogue_ssh_key
    The test failed in the call phase due to an assertion error
    E       AssertionError: Attacker's SSH key still present
    E       assert 'attacker' not in 'ssh-ed25519...cker@pwned\n'
    E         'attacker' is contained here:
    E           0YWNrZXIK attacker@pwned
    E         ?           ++++++++
    E           ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGJhY2tkb29yX2tleV9mb3JfYXR0YWNrZXIK attacker@pwned
    E           ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGJhY2tkb29yX2tleV9mb3JfYXR0YWNrZXIK attacker@pwned
    E           ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGJhY2tkb29yX2tleV9mb3JfYXR0YWNrZXIK attacker@pwned
    E           ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGJhY2tkb29yX2tleV9mb3JfYXR0YWNrZXIK attacker@pwned
    E           ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGJhY2tkb29yX2tleV9mb3JfYXR0YWNrZXIK attacker@pwned

  ✗ test_no_backdoor_persistence
    The test failed in the call phase due to an assertion error
    E       AssertionError: Backdoor cron file /etc/cron.d/apt-compat still exists
    E       assert 'gone' in 'exists\n'
    E        +  where 'exists\n' = CompletedProcess(args='test -f /etc/cron.d/apt-compat && echo exists || echo gone', returncode=0, stdout='exists\n', stderr='').stdout

  ✗ test_backdoor_key_stays_removed
    The test failed in the call phase due to an assertion error
    E       AssertionError: Attacker key reappeared — persistence mechanism not fully removed
    E       assert 'attacker' not in 'ssh-ed25519...cker@pwned\n'
    E         'attacker' is contained here:
    E           0YWNrZXIK attacker@pwned
    E         ?           ++++++++

  ✗ test_input_null_byte_rejected
    The test failed in the call phase due to an assertion error
    E       AssertionError: Null byte in name should return 400, got 200
    E       assert 200 == 400
    E        +  where 200 = <Response [200]>.status_code
```

Here is the terminal actions it took
![](./assets/compromised-prod-server-easy-best.gif)

the worst results:
```
============================================================
TRIAL: compromised-prod-server-easy__unirjD2
============================================================
  Agent:     terminus-2
  Task:      dipankardas/compromised-prod-server-easy
  Reward:    0.0 ✗
  environment_setup        0:00:03
  agent_setup              0:00:53
  agent_execution          0:05:28
  verifier                 0:02:25

  Tests: 8/30 passed, 22 failed

    ✓ test_ssh_access                          (0.22s)
    ✓ test_ssh_key_permissions                 (0.00s)
    ✗ test_no_rogue_ssh_key                    (0.00s)
    ✓ test_prod_svr_authorized_keys_intact     (0.23s)
    ✗ test_no_backdoor_persistence             (0.00s)
    ✗ test_backdoor_key_stays_removed          (70.01s)
    ✓ test_jumphost_root_ca_in_place           (0.07s)
    ✓ test_nginx_config_valid                  (0.28s)
    ✓ test_ssl_chain_valid                     (0.29s)
    ✗ test_healthz_endpoint                    (0.01s)
    ✗ test_basic_auth_required                 (0.01s)
    ✗ test_basic_auth_works                    (0.01s)
    ✗ test_response_contains_name              (0.01s)
    ✗ test_response_is_ascii                   (0.01s)
    ✗ test_response_format                     (0.01s)
    ✗ test_cors_headers                        (0.00s)
    ✗ test_cors_preflight_options              (0.00s)
    ✗ test_security_header_nosniff             (0.00s)
    ✗ test_security_header_frame_options       (0.01s)
    ✗ test_security_header_hsts                (0.00s)
    ✗ test_input_length_limit                  (0.00s)
    ✗ test_input_xss_escaped                   (0.01s)
    ✗ test_input_non_ascii_rejected            (0.00s)
    ✗ test_input_null_byte_rejected            (0.00s)
    ✗ test_method_not_allowed_post             (0.00s)
    ✗ test_method_not_allowed_delete           (0.00s)
    ✗ test_path_traversal_blocked              (0.01s)
    ✗ test_wrong_basic_auth_rejected           (0.01s)
    ✓ test_go_unit_tests_handlers              (2.66s)
    ✓ test_app_not_running_as_root             (0.44s)

  ──────────────────────────────────────────────────
  FAILURE DETAILS
  ──────────────────────────────────────────────────

  ✗ test_no_rogue_ssh_key
    The test failed in the call phase due to an assertion error
    E       AssertionError: Attacker's SSH key still present
    E       assert 'attacker' not in 'ssh-ed25519...cker@pwned\n'
    E         'attacker' is contained here:
    E           0YWNrZXIK attacker@pwned
    E         ?           ++++++++
    E           ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGJhY2tkb29yX2tleV9mb3JfYXR0YWNrZXIK attacker@pwned
    E           ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGJhY2tkb29yX2tleV9mb3JfYXR0YWNrZXIK attacker@pwned
    E           ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGJhY2tkb29yX2tleV9mb3JfYXR0YWNrZXIK attacker@pwned
    E           ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGJhY2tkb29yX2tleV9mb3JfYXR0YWNrZXIK attacker@pwned
    E           ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGJhY2tkb29yX2tleV9mb3JfYXR0YWNrZXIK attacker@pwned

  ✗ test_no_backdoor_persistence
    The test failed in the call phase due to an assertion error
    E       AssertionError: Backdoor cron file /etc/cron.d/apt-compat still exists
    E       assert 'gone' in 'exists\n'
    E        +  where 'exists\n' = CompletedProcess(args='test -f /etc/cron.d/apt-compat && echo exists || echo gone', returncode=0, stdout='exists\n', stderr='').stdout

  ✗ test_backdoor_key_stays_removed
    The test failed in the call phase due to an assertion error
    E       AssertionError: Attacker key reappeared — persistence mechanism not fully removed
    E       assert 'attacker' not in 'ssh-ed25519...cker@pwned\n'
    E         'attacker' is contained here:
    E           0YWNrZXIK attacker@pwned
    E         ?           ++++++++

  ✗ test_healthz_endpoint
    The test failed in the call phase due to an exception
    E           ssl.SSLCertVerificationError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)
    E           urllib3.exceptions.SSLError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)
    E           urllib3.exceptions.MaxRetryError: HTTPSConnectionPool(host='prod-svr', port=443): Max retries exceeded with url: /healthz (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)')))
    E               requests.exceptions.SSLError: HTTPSConnectionPool(host='prod-svr', port=443): Max retries exceeded with url: /healthz (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)')))

  ✗ test_basic_auth_required
    The test failed in the call phase due to an exception
    E           ssl.SSLCertVerificationError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)
    E           urllib3.exceptions.SSLError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)
    E           urllib3.exceptions.MaxRetryError: HTTPSConnectionPool(host='prod-svr', port=443): Max retries exceeded with url: /home?name=test (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)')))
    E               requests.exceptions.SSLError: HTTPSConnectionPool(host='prod-svr', port=443): Max retries exceeded with url: /home?name=test (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)')))

  ✗ test_basic_auth_works
    The test failed in the call phase due to an exception
    E           ssl.SSLCertVerificationError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)
    E           urllib3.exceptions.SSLError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)
    E           urllib3.exceptions.MaxRetryError: HTTPSConnectionPool(host='prod-svr', port=443): Max retries exceeded with url: /home?name=test (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)')))
    E               requests.exceptions.SSLError: HTTPSConnectionPool(host='prod-svr', port=443): Max retries exceeded with url: /home?name=test (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)')))

  ✗ test_response_contains_name
    The test failed in the call phase due to an exception
    E           ssl.SSLCertVerificationError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)
    E           urllib3.exceptions.SSLError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)
    E           urllib3.exceptions.MaxRetryError: HTTPSConnectionPool(host='prod-svr', port=443): Max retries exceeded with url: /home?name=world (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)')))
    E               requests.exceptions.SSLError: HTTPSConnectionPool(host='prod-svr', port=443): Max retries exceeded with url: /home?name=world (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)')))

  ✗ test_response_is_ascii
    The test failed in the call phase due to an exception
    E           ssl.SSLCertVerificationError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)
    E           urllib3.exceptions.SSLError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)
    E           urllib3.exceptions.MaxRetryError: HTTPSConnectionPool(host='prod-svr', port=443): Max retries exceeded with url: /home?name=test (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)')))
    E               requests.exceptions.SSLError: HTTPSConnectionPool(host='prod-svr', port=443): Max retries exceeded with url: /home?name=test (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)')))

  ✗ test_response_format
    The test failed in the call phase due to an exception
    E           ssl.SSLCertVerificationError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)
    E           urllib3.exceptions.SSLError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)
    E           urllib3.exceptions.MaxRetryError: HTTPSConnectionPool(host='prod-svr', port=443): Max retries exceeded with url: /home?name=world (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)')))
    E               requests.exceptions.SSLError: HTTPSConnectionPool(host='prod-svr', port=443): Max retries exceeded with url: /home?name=world (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)')))

  ✗ test_cors_headers
    The test failed in the call phase due to an exception
    E           ssl.SSLCertVerificationError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)
    E           urllib3.exceptions.SSLError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)
    E           urllib3.exceptions.MaxRetryError: HTTPSConnectionPool(host='prod-svr', port=443): Max retries exceeded with url: /home?name=test (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)')))
    E               requests.exceptions.SSLError: HTTPSConnectionPool(host='prod-svr', port=443): Max retries exceeded with url: /home?name=test (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)')))

  ✗ test_cors_preflight_options
    The test failed in the call phase due to an exception
    E           ssl.SSLCertVerificationError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)
    E           urllib3.exceptions.SSLError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)
    E           urllib3.exceptions.MaxRetryError: HTTPSConnectionPool(host='prod-svr', port=443): Max retries exceeded with url: /home (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)')))
    E               requests.exceptions.SSLError: HTTPSConnectionPool(host='prod-svr', port=443): Max retries exceeded with url: /home (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)')))

  ✗ test_security_header_nosniff
    The test failed in the call phase due to an exception
    E           ssl.SSLCertVerificationError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)
    E           urllib3.exceptions.SSLError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)
    E           urllib3.exceptions.MaxRetryError: HTTPSConnectionPool(host='prod-svr', port=443): Max retries exceeded with url: /home?name=test (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)')))
    E               requests.exceptions.SSLError: HTTPSConnectionPool(host='prod-svr', port=443): Max retries exceeded with url: /home?name=test (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)')))

  ✗ test_security_header_frame_options
    The test failed in the call phase due to an exception
    E           ssl.SSLCertVerificationError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)
    E           urllib3.exceptions.SSLError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)
    E           urllib3.exceptions.MaxRetryError: HTTPSConnectionPool(host='prod-svr', port=443): Max retries exceeded with url: /home?name=test (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)')))
    E               requests.exceptions.SSLError: HTTPSConnectionPool(host='prod-svr', port=443): Max retries exceeded with url: /home?name=test (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)')))

  ✗ test_security_header_hsts
    The test failed in the call phase due to an exception
    E           ssl.SSLCertVerificationError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)
    E           urllib3.exceptions.SSLError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)
    E           urllib3.exceptions.MaxRetryError: HTTPSConnectionPool(host='prod-svr', port=443): Max retries exceeded with url: /home?name=test (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)')))
    E               requests.exceptions.SSLError: HTTPSConnectionPool(host='prod-svr', port=443): Max retries exceeded with url: /home?name=test (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)')))

  ✗ test_input_length_limit
    The test failed in the call phase due to an exception
    E           ssl.SSLCertVerificationError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)
    E           urllib3.exceptions.SSLError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)
    E           urllib3.exceptions.MaxRetryError: HTTPSConnectionPool(host='prod-svr', port=443): Max retries exceeded with url: /home?name=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)')))
    E               requests.exceptions.SSLError: HTTPSConnectionPool(host='prod-svr', port=443): Max retries exceeded with url: /home?name=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)')))

  ✗ test_input_xss_escaped
    The test failed in the call phase due to an exception
    E           ssl.SSLCertVerificationError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)
    E           urllib3.exceptions.SSLError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)
    E           urllib3.exceptions.MaxRetryError: HTTPSConnectionPool(host='prod-svr', port=443): Max retries exceeded with url: /home?name=%3Cscript%3Ealert%281%29%3C%2Fscript%3E (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)')))
    E               requests.exceptions.SSLError: HTTPSConnectionPool(host='prod-svr', port=443): Max retries exceeded with url: /home?name=%3Cscript%3Ealert%281%29%3C%2Fscript%3E (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)')))

  ✗ test_input_non_ascii_rejected
    The test failed in the call phase due to an exception
    E           ssl.SSLCertVerificationError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)
    E           urllib3.exceptions.SSLError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)
    E           urllib3.exceptions.MaxRetryError: HTTPSConnectionPool(host='prod-svr', port=443): Max retries exceeded with url: /home?name=w%C3%B6rld (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)')))
    E               requests.exceptions.SSLError: HTTPSConnectionPool(host='prod-svr', port=443): Max retries exceeded with url: /home?name=w%C3%B6rld (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)')))

  ✗ test_input_null_byte_rejected
    The test failed in the call phase due to an exception
    E           ssl.SSLCertVerificationError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)
    E           urllib3.exceptions.SSLError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)
    E           urllib3.exceptions.MaxRetryError: HTTPSConnectionPool(host='prod-svr', port=443): Max retries exceeded with url: /home?name=hello%00world (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)')))
    E               requests.exceptions.SSLError: HTTPSConnectionPool(host='prod-svr', port=443): Max retries exceeded with url: /home?name=hello%00world (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)')))

  ✗ test_method_not_allowed_post
    The test failed in the call phase due to an exception
    E           ssl.SSLCertVerificationError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)
    E           urllib3.exceptions.SSLError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)
    E           urllib3.exceptions.MaxRetryError: HTTPSConnectionPool(host='prod-svr', port=443): Max retries exceeded with url: /home?name=test (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)')))
    E               requests.exceptions.SSLError: HTTPSConnectionPool(host='prod-svr', port=443): Max retries exceeded with url: /home?name=test (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)')))

  ✗ test_method_not_allowed_delete
    The test failed in the call phase due to an exception
    E           ssl.SSLCertVerificationError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)
    E           urllib3.exceptions.SSLError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)
    E           urllib3.exceptions.MaxRetryError: HTTPSConnectionPool(host='prod-svr', port=443): Max retries exceeded with url: /home (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)')))
    E               requests.exceptions.SSLError: HTTPSConnectionPool(host='prod-svr', port=443): Max retries exceeded with url: /home (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)')))

  ✗ test_path_traversal_blocked
    The test failed in the call phase due to an exception
    E           ssl.SSLCertVerificationError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)
    E           urllib3.exceptions.SSLError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)
    E           urllib3.exceptions.MaxRetryError: HTTPSConnectionPool(host='prod-svr', port=443): Max retries exceeded with url: /etc/passwd (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)')))
    E               requests.exceptions.SSLError: HTTPSConnectionPool(host='prod-svr', port=443): Max retries exceeded with url: /etc/passwd (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)')))

  ✗ test_wrong_basic_auth_rejected
    The test failed in the call phase due to an exception
    E           ssl.SSLCertVerificationError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)
    E           urllib3.exceptions.SSLError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)
    E           urllib3.exceptions.MaxRetryError: HTTPSConnectionPool(host='prod-svr', port=443): Max retries exceeded with url: /home?name=test (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)')))
    E               requests.exceptions.SSLError: HTTPSConnectionPool(host='prod-svr', port=443): Max retries exceeded with url: /home?name=test (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)')))
```


Here is the terminal actions it took
![](./assets/compromised-prod-server-easy-worst.gif)

</details>
