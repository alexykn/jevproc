"""Apply cohesive, behavior-preserving core refactors to the checked-out base."""
from _architecture_tools import add_imports, append, read, replace, write


def apply():
    config = 'src/jevproc/core/config.py'
    append(config, '''
def _read_override(path: Path) -> dict:
    with path.open("rb") as handle:
        raw = handle.read(262145)
    if len(raw) > 262144:
        raise ConfigError("configuration exceeds 256 KiB")
    override = yaml.load(raw, Loader=UniqueSafeLoader)
    if not isinstance(override, dict):
        raise ConfigError("configuration must be a YAML mapping")
    return override


def _patch_rules(existing: list[dict], patches: object) -> list[dict]:
    if not isinstance(patches, list) or not all(
        isinstance(rule, dict) and isinstance(rule.get("id"), str) for rule in patches
    ):
        raise ConfigError("each ruleset must contain rule mappings with an id")
    if len({rule["id"] for rule in patches}) != len(patches):
        raise ConfigError("duplicate rule ID in a ruleset override")
    by_id = {rule["id"]: rule for rule in existing}
    for rule in patches:
        by_id[rule["id"]] = _merge(by_id.get(rule["id"], {}), rule)
    return list(by_id.values())


def _apply_override(defaults: dict, override: dict) -> dict:
    additions = override.get("rulesets", {})
    if not isinstance(additions, dict):
        raise ConfigError("rulesets must be a mapping")
    rulesets = dict(defaults["rulesets"])
    for name, rules in additions.items():
        rulesets[name] = _patch_rules(rulesets.get(name, []), rules)
    settings = {key: value for key, value in override.items() if key != "rulesets"}
    return _merge({**defaults, "rulesets": rulesets}, settings)
''')
    replace(config, 'load_config', '''
def load_config(path: Path | None = None) -> Config:
    """Load packaged defaults and only an explicitly selected operator override."""
    try:
        data = yaml.load(default_yaml(), Loader=UniqueSafeLoader)
        if path is not None:
            data = _apply_override(data, _read_override(path))
        return Config.model_validate(data)
    except (OSError, yaml.YAMLError, ValidationError, UnicodeError, RecursionError) as exc:
        # Config values may contain accidental secrets; report the failure type only.
        raise ConfigError(f"invalid or unreadable configuration ({type(exc).__name__})") from exc
''')

    storage = 'src/jevproc/core/storage.py'
    add_imports(storage, 'from contextlib import ExitStack')
    append(storage, '''
def _prepare_cache_file(directory: Path) -> Path:
    """Acquire and validate the private disk file, always releasing its descriptor."""
    _private_directory(directory)
    path = directory / "answers.sqlite3"
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_mode & 0o077 or info.st_nlink != 1):
            raise StorageError("cache must be a private, owned regular file with one link")
    finally:
        os.close(fd)
    return path


def _open_cache_database(path: Path) -> sqlite3.Connection:
    """Transfer ownership only after setup succeeds; close on every failure path."""
    with ExitStack() as cleanup:
        db = sqlite3.connect(path, timeout=5)
        cleanup.callback(db.close)
        db.execute("PRAGMA trusted_schema=OFF")
        db.execute("CREATE TABLE IF NOT EXISTS answers (key TEXT PRIMARY KEY, expires REAL NOT NULL, body BLOB NOT NULL)")
        db.commit()
        cleanup.pop_all()
    return db
''')
    replace(storage, 'AnswerCache.__init__', '''
def __init__(self, directory: Path, settings: CacheSettings):
    self.db = _open_cache_database(_prepare_cache_file(directory))
    self.settings = settings
''')

    privacy = 'src/jevproc/core/privacy.py'
    add_imports(privacy, 'from collections.abc import Iterator')
    append(privacy, '''
def _secret_flag(value: str) -> tuple[str, bool]:
    flag, separator, _ = value.partition("=")
    key = flag.lstrip("-").lower().replace("_", "-")
    if not flag.startswith("-") or key not in _SECRET_FLAGS:
        return value, False
    return (flag + "=<redacted>", False) if separator else (value, True)


def _redacted_arguments(arguments: list[str]) -> Iterator[str]:
    """Track split secret values, including a separate Bearer/Basic scheme."""
    redact_next = False
    for index, value in enumerate(arguments):
        if redact_next:
            redact_next = value.lower() in {"bearer", "basic"}
            value = "<redacted>"
        elif index:
            value, redact_next = _secret_flag(value)
        yield redact_text(value)
''')
    replace(privacy, 'redact_argv', '''
def redact_argv(arguments: list[str]) -> tuple[list[str], bool]:
    """Redact first, then apply the wire limits without exposing a partial secret."""
    result: list[str] = []
    shortened = len(arguments) > 64
    for cleaned in _redacted_arguments(arguments[:64]):
        if len(cleaned) > 512:
            cleaned = cleaned[:498] + "...<truncated>"
            shortened = True
        result.append(cleaned)
    return result, shortened
''')

    assessment = 'src/jevproc/core/assessment.py'
    add_imports(assessment, 'from dataclasses import dataclass\nfrom jevproc.core.config import Policy')
    append(assessment, '''
@dataclass(frozen=True)
class _Decision:
    status: Status
    value: float | str
    probability: float | None = None
    confidence: float | None = None


def _noul_decision(policy: Policy, answer: NoulAnswer, limited: bool) -> _Decision:
    value = answer.noul
    if value >= policy.warning_at and not limited:
        status: Status = "warning"
    elif value >= policy.uncertain_at:
        status = "uncertain_warning"
    else:
        status = "unknown" if limited else "probably_legitimate"
    return _Decision(status, value, probability=value)


def _choice_decision(policy: Policy, answer: ChoiceAnswer, limited: bool) -> _Decision:
    probability = answer.probabilities[answer.choice]
    confident = probability >= policy.warning_at and answer.confidence >= policy.confidence_min and not limited
    selected_risk = answer.choice in policy.warning_choices
    # Provider supports need not sum to one: never synthesize a summed risk.
    risk_support = max(answer.probabilities[label] for label in policy.warning_choices)
    if selected_risk and confident:
        status: Status = "warning"
    elif selected_risk or risk_support >= policy.uncertain_at:
        status = "uncertain_warning"
    elif answer.choice in policy.legitimate_choices and confident:
        status = "probably_legitimate"
    else:
        status = "unknown"
    return _Decision(status, answer.choice, probability, answer.confidence)


def _score_decision(policy: Policy, answer: ScoreAnswer, limited: bool) -> _Decision:
    if answer.score >= policy.score_warning_at and answer.confidence >= policy.confidence_min and not limited:
        status: Status = "warning"
    elif answer.score >= policy.score_uncertain_at:
        status = "uncertain_warning"
    else:
        status = "unknown" if answer.confidence < policy.confidence_min else "no_warning"
    return _Decision(status, answer.score, confidence=answer.confidence)


def _decide(policy: Policy, answer: Answer, limited: bool) -> _Decision:
    if isinstance(answer, NoulAnswer):
        return _noul_decision(policy, answer, limited)
    if isinstance(answer, ChoiceAnswer):
        return _choice_decision(policy, answer, limited)
    assert isinstance(answer, ScoreAnswer)
    return _score_decision(policy, answer, limited)
''')
    replace(assessment, 'judge', '''
def judge(rule: Rule, process: Process, answer: Answer) -> RuleResult:
    limited = evidence_limited(rule, process)
    decision = _decide(rule.policy, answer, limited)
    message = rule.message if decision.status in VISIBLE else ""
    if limited and decision.status in VISIBLE:
        message += " Relevant evidence is partial or unavailable; this finding remains uncertain."
    return RuleResult(
        rule=rule.id, title=rule.title, status=decision.status, message=message,
        value=decision.value, probability=decision.probability, confidence=decision.confidence,
        answer=answer.model_dump(mode="json"),
    )
''')

    client = 'src/jevproc/core/client.py'
    append(client, '''
async def _read_bounded_response(response: httpx.Response) -> httpx.Response:
    """Consume and detach a decoded response without retaining transport resources."""
    parts: list[bytes] = []
    size = 0
    async for part in response.aiter_bytes(chunk_size=65536):
        size += len(part)
        if size > 2 * 1024 * 1024:
            raise JevError("Jev response exceeds the 2 MiB safety limit")
        parts.append(part)
    headers = response.headers.copy()
    headers.pop("content-encoding", None)
    headers.pop("content-length", None)
    return httpx.Response(response.status_code, headers=headers, content=b"".join(parts))


def _raise_permanent_failure(response: httpx.Response) -> None:
    if _context_error(response):
        raise ContextLimitError("Jev rejected the context size")
    if response.status_code in {400, 422}:
        raise RequestRejectedError(
            status=response.status_code,
            machine_fields=_machine_fields(_json_body(response)),
            request_id=_safe_request_id(response),
        )
    if response.status_code not in {408, 429} and response.status_code < 500:
        request_id = _safe_request_id(response)
        suffix = f"; request-id={request_id}" if request_id else ""
        raise JevError(f"Jev request failed (HTTP {response.status_code}{suffix})")
''')
    replace(client, 'JevClient._post', '''
async def _post(self, body: bytes) -> httpx.Response:
    async with self.slots:
        self._check_ready()
        await self.limiter.acquire()
        self._check_ready()
        self.requests += 1
        async with self.http.stream("POST", "/v1/systemone", content=body) as response:
            result = await _read_bounded_response(response)
        if result.status_code in {401, 403}:
            self.fatal_error = f"Jev authentication/authorization failed (HTTP {result.status_code})"
        return result
''')
    # Add cohesive methods before the existing backoff method, without a new transport framework.
    source = read(client)
    marker = '    def _backoff('
    methods = '''
    def _accept_response(self, response: httpx.Response, questions: dict[str, Question]) -> JevResponse:
        validated = validate_response(response.content, questions)
        if self.settings.model not in {"jev-latest", "jev-preview"} and validated.model != self.settings.model:
            raise JevError("Jev returned a different model than the requested pinned version")
        self.input_tokens += validated.usage.input_tokens
        self.output_tokens += validated.usage.output_tokens
        return validated

    def _transport_retry(self, error: httpx.RequestError, attempt: int) -> float:
        if attempt == self.settings.retries:
            raise JevError(f"Jev transport failed ({type(error).__name__}); no response was classified") from error
        return self._backoff(attempt)

    def _response_retry(self, response: httpx.Response, attempt: int) -> float:
        _raise_permanent_failure(response)
        if attempt == self.settings.retries:
            raise JevError(f"Jev retries exhausted (HTTP {response.status_code})")
        provider_delay = retry_after(response.headers)
        delay = self._backoff(attempt) if provider_delay is None else provider_delay
        if delay > self.settings.max_retry_delay:
            raise JevError("Jev Retry-After exceeds max_retry_delay; refusing to retry early")
        return delay

'''
    assert marker in source
    write(client, source.replace(marker, methods + marker, 1))
    replace(client, 'JevClient.evaluate', '''
async def evaluate(self, body: bytes, questions: dict[str, Question]) -> JevResponse:
    for attempt in range(self.settings.retries + 1):
        try:
            response = await self._post(body)
        except httpx.RequestError as exc:
            delay = self._transport_retry(exc, attempt)
        else:
            if response.is_success:
                return self._accept_response(response, questions)
            delay = self._response_retry(response, attempt)
            # Preserve shared overload pacing, independently of a worker's own sleep.
            self.limiter.defer(delay)
        self.retries += 1
        await asyncio.sleep(delay)
    raise AssertionError("retry loop must return or raise")
''')

    engine = 'src/jevproc/core/engine.py'
    add_imports(engine, 'from jevproc.core.protocol import EvaluationRequest, JevResponse\nfrom jevproc.core.config import Question')
    source = read(engine)
    start = source.index('        counts = Counter(assessment.status for assessment in assessments)')
    end = source.index('        return Report(', start)
    summary_block = source[start:end]
    summary_block = summary_block.replace('        after = self._counters()\n', '')
    import textwrap
    summary_block = textwrap.dedent(summary_block).replace('summary = {', 'return {', 1)
    append(engine, '''
def _scan_summary(snapshot: Snapshot, assessments: list[Assessment], before: tuple[int, int, int, int],
                  after: tuple[int, int, int, int], started: float) -> dict:
''' + textwrap.indent(summary_block, '    '))
    source = read(engine)
    marker = '    async def _evaluate('
    methods = '''
    def _cached_answer(self, key: str, questions: dict[str, Question]) -> JevResponse | None:
        if self.cache is None:
            return None
        answer = self.cache.get(key, questions)
        if answer and self.config.jev.model not in {"jev-latest", "jev-preview"} and answer.model != self.config.jev.model:
            self.cache.delete(key)
            return None
        return answer

    async def _answer(self, request: EvaluationRequest) -> tuple[JevResponse, bool]:
        assert self.client is not None
        key = request_key(self.client.base_url, request.body)
        cached = self._cached_answer(key, request.questions)
        if cached is not None:
            return cached, True
        answer = await self.client.evaluate(request.body, request.questions)
        if self.cache is not None:
            self.cache.put(key, answer)
        return answer, False

'''
    assert marker in source
    write(engine, source.replace(marker, methods + marker, 1))
    replace(engine, 'Engine._evaluate', '''
async def _evaluate(self, snapshot: Snapshot, process: Process) -> Assessment:
    request = make_request(snapshot, process, self.config)
    if not request.checks:
        return _unavailable(process, "No configured rules have the required evidence.")
    try:
        answer, cached = await self._answer(request)
    except ContextLimitError:
        return _unavailable(process, "This process request exceeded Jev's context limit; no evidence was silently truncated.", failure=True)
    except JevError as exc:
        return _unavailable(process, str(exc), failure=True)
    return assess(process, self.config.active_rules, answer.answers, answer.model, cached)
''')
    source = read(engine)
    marker = '    def _counters('
    worker = '''
    async def _worker(self, snapshot: Snapshot, queue: asyncio.Queue[Process],
                      assessments: list[Assessment], on_assessment: Callable[[Assessment], None] | None) -> None:
        while True:
            try:
                process = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            result = await self._evaluate(snapshot, process)
            assessments.append(result)
            if on_assessment is not None:
                on_assessment(result)

    async def _evaluate_pending(self, snapshot: Snapshot, candidates: list[Process],
                                assessments: list[Assessment], on_assessment: Callable[[Assessment], None] | None) -> None:
        queue: asyncio.Queue[Process] = asyncio.Queue()
        for process in candidates:
            queue.put_nowait(process)
        async with asyncio.TaskGroup() as group:
            for _ in range(min(self.config.jev.concurrency, len(candidates))):
                group.create_task(self._worker(snapshot, queue, assessments, on_assessment))

'''
    assert marker in source
    write(engine, source.replace(marker, worker + marker, 1))
    append(engine, '''
def _initial_assessment(process: Process, mode: str) -> Assessment | None:
    if mode == "offline":
        return _unavailable(process, "Offline inventory only; Jev did not classify this process.")
    if process.freshness != "observed" or process.created_at is None:
        return _unavailable(process, f"Process identity is {process.freshness}; not submitted to Jev.")
    return None
''')
    replace(engine, 'Engine.scan', '''
async def scan(self, snapshot: Snapshot, mode: Literal["live", "offline", "demo"] = "live",
               on_assessment: Callable[[Assessment], None] | None = None) -> Report:
    started = time.monotonic()
    before = self._counters()
    assessments: list[Assessment] = []
    candidates: list[Process] = []
    for process in snapshot.processes:
        initial = _initial_assessment(process, mode)
        if initial is None:
            candidates.append(process)
            continue
        assessments.append(initial)
        if on_assessment is not None:
            on_assessment(initial)
    await self._evaluate_pending(snapshot, candidates, assessments, on_assessment)
    assessments.sort(key=lambda assessment: assessment.process.pid)
    return Report(mode=mode, snapshot_time=snapshot.captured_at, model_requested=self.config.jev.model,
                  assessments=assessments,
                  summary=_scan_summary(snapshot, assessments, before, self._counters(), started))
''')
