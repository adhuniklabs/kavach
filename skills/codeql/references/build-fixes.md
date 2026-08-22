# Build Fixes

Fixes to apply when a CodeQL database build method fails. Try these in order, then retry the current build method. **Log each fix attempt.**

## 1. Clean existing state

```bash
log_step "Applying fix: clean existing state"
rm -rf "$DB_NAME"
log_result "Removed $DB_NAME"
```

## 2. Clean build cache

```bash
log_step "Applying fix: clean build cache"
CLEANED=""
make clean 2>/dev/null && CLEANED="$CLEANED make"
rm -rf build CMakeCache.txt CMakeFiles 2>/dev/null && CLEANED="$CLEANED cmake-artifacts"
./gradlew clean 2>/dev/null && CLEANED="$CLEANED gradle"
mvn clean 2>/dev/null && CLEANED="$CLEANED maven"
cargo clean 2>/dev/null && CLEANED="$CLEANED cargo"
log_result "Cleaned: $CLEANED"
```

## 3. Install missing dependencies

> **Note:** The commands below install the *target project's* dependencies so CodeQL can trace the build. Use whatever package manager the target project expects (`pip`, `npm`, `go mod`, etc.) - these are not the skill's own tooling preferences.

```bash
log_step "Applying fix: install dependencies"

# Python - use target project's package manager (pip/uv/poetry)
if [ -f requirements.txt ]; then
  log_cmd "pip install -r requirements.txt"
  pip install -r requirements.txt 2>&1 | tee -a "$LOG_FILE"
fi
if [ -f setup.py ] || [ -f pyproject.toml ]; then
  log_cmd "pip install -e ."
  pip install -e . 2>&1 | tee -a "$LOG_FILE"
fi

# Node - log installed packages
if [ -f package.json ]; then
  log_cmd "npm install"
  npm install 2>&1 | tee -a "$LOG_FILE"
fi

# Go
if [ -f go.mod ]; then
  log_cmd "go mod download"
  go mod download 2>&1 | tee -a "$LOG_FILE"
fi

# Java - log downloaded dependencies
if [ -f build.gradle ] || [ -f build.gradle.kts ]; then
  log_cmd "./gradlew dependencies --refresh-dependencies"
  ./gradlew dependencies --refresh-dependencies 2>&1 | tee -a "$LOG_FILE"
fi
if [ -f pom.xml ]; then
  log_cmd "mvn dependency:resolve"
  mvn dependency:resolve 2>&1 | tee -a "$LOG_FILE"
fi

# Rust
if [ -f Cargo.toml ]; then
  log_cmd "cargo fetch"
  cargo fetch 2>&1 | tee -a "$LOG_FILE"
fi

log_result "Dependencies installed - see above for details"
```

## 4. Handle private registries

If dependencies require authentication that isn't already configured in the environment (e.g. a
private npm/PyPI/Maven registry token), don't stop the run to ask for credentials - this is a
zero-input skill. Skip the affected build method, log exactly what's missing (`registry URL`,
which dependency needed it), and fall through to the next build method (or the no-build fallback).
Note the gap in the final report so the operator can supply registry auth and re-run if they want
full build tracing for that language.

```bash
log_step "Private registry access unavailable - skipping affected dependency, falling through"
log_result "Registry: <REGISTRY_URL>, dependency: <DEP_NAME> - build method degraded, noted for operator"
```

**After fixes:** Retry current build method. If still fails, move to next method.
