VENV=.venv
PY=$(VENV)/bin/python
PIP=$(VENV)/bin/pip

.PHONY: venv demo smoke success captures migrate-request fs picotls-build picotls-test interop openssl-interop clean

venv:
	python3 -m venv $(VENV)
	$(PIP) install -q -r requirements.txt

demo: ## run all scenarios
	cd tlslite_poc && ../$(PY) demo.py

success: ## run the success scenario with byte-level evidence
	cd tlslite_poc && ../$(PY) demo.py success

smoke: ## minimal cross-instance resumption check
	cd tlslite_poc && ../$(PY) _smoke.py

captures: ## produce + decode real wire-byte artifacts
	cd tlslite_poc && ../$(PY) captures.py && ../$(PY) decode.py

migrate-request: ## prove migrate_request as a real post-handshake message
	cd tlslite_poc && ../$(PY) migrate_request_wire.py

fs: ## forward-secrecy enforcement (psk_dhe_ke required, psk_ke refused)
	cd tlslite_poc && ../$(PY) fs_enforcement.py

openssl-interop: ## mainstream-stack interop: OpenSSL <-> tlslite-ng (migration_support)
	bash openssl-integration/run_openssl_interop.sh

picotls-build:
	cd picotls && cmake -DOPENSSL_ROOT_DIR="$$(brew --prefix openssl@3)" . && $(MAKE) -j4 cli test-openssl.t

picotls-test:
	cd picotls && ./test-openssl.t | tail -5

interop: ## cross-stack picotls <-> tlslite-ng interop (both directions)
	bash picotls-integration/run_interop.sh

clean:
	rm -rf tlslite_poc/__pycache__ tlslite_poc/cert.pem tlslite_poc/key.pem
