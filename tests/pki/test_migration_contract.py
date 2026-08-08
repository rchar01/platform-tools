import ast
import re
import shlex
from pathlib import Path

import pytest
import yaml

from .migration_contract import (
    ACTIVE_ISSUER_FIELDS,
    BACKUP_RECEIPT_FIELDS,
    CSR_DB_KEYS,
    FAULT_HOOK_CONTRACTS,
    GENERATION_RESERVATION_BOOTSTRAP_CONSUMED_FIELDS,
    GENERATION_RESERVATION_MIGRATION_FIELDS,
    GENERATION_RESERVATION_TRANSACTION_FIELDS,
    INTERMEDIATE_BOOTSTRAP_DB_FIELDS,
    INTERMEDIATE_BOOTSTRAP_JOURNAL_FIELDS,
    INTERMEDIATE_BOOTSTRAP_PREFIX_FIELDS,
    INTERMEDIATE_BOOTSTRAP_RECOVERY_FIELDS,
    LEGACY_MIGRATION_CHECKPOINT_FIELDS,
    LEGACY_MIGRATION_JOURNAL_FIELDS,
    LEGACY_MIGRATION_RECOVERY_FIELDS,
    LOCK_ORDER,
    MIGRATION_QUARANTINE_NAMES,
    PILOT_INSTALLED_ASSET_CONTRACTS,
    PILOT_OUTPUT_STATUS_CONTRACTS,
    PILOT_RUNTIME_DEPENDENCY_CONTRACTS,
    PERSISTED_RECORD_CONTRACTS,
    PKI_COMMAND_CONTRACTS,
    PKI_DUPLICATE_OPTION_CONTRACTS,
    PKI_PARSER_ROUTES,
    PKI_RUNTIME_OPTION_RELATIONSHIPS,
    RECOVERY_CONTRACTS,
    ROLLOVER_PREPARE_BASE_FIELDS,
    ROLLOVER_PREPARE_JOURNAL_FIELDS,
    ROLLOVER_PREPARE_PREPARTIAL_FIELDS,
    ROLLOVER_PREPARE_PREPARTIAL_NAMES,
    ROLLOVER_PREPARE_ROOT_DB_FIELDS,
    ROLLOVER_PREPARED_MANIFEST_FIELDS,
    ROOT_BOOTSTRAP_JOURNAL_FIELDS,
    ROOT_BOOTSTRAP_RECOVERY_FIELDS,
    ROOT_DB_KEYS,
    ParserRouteContract,
)


pytestmark = pytest.mark.infrastructure
ROOT = Path(__file__).parents[2]


def _source(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def _source_record_block(path: str, start: str, end: str) -> str:
    source = _source(path)
    block_start = source.index(start) + len(start)
    block_end = source.index(end, block_start)
    return source[block_start:block_end]


def _record_fields(block: str) -> tuple[str, ...]:
    return tuple(re.findall(r"(?m)^([a-z][a-z0-9_]*)=", block))


def _source_record_fields(path: str, start: str, end: str) -> tuple[str, ...]:
    return _record_fields(_source_record_block(path, start, end))


def _record_fields_after_atomic_write(
    source: str,
    first_field: str,
) -> tuple[tuple[str, ...], ...]:
    blocks = re.findall(
        rf'pki_atomic_write[^\n]*?"({re.escape(first_field)}=.*?)\n"',
        source,
        re.DOTALL,
    )
    return tuple(_record_fields(block) for block in blocks)


def _generation_record_fields(path: str) -> tuple[tuple[str, ...], ...]:
    return _record_fields_after_atomic_write(_source(path), "generation")


def _literal_for_fields(source: str, first_field: str) -> tuple[str, ...]:
    match = re.search(
        rf"for field in ({re.escape(first_field)}(?: [a-z0-9_]+)*); do",
        source,
    )
    assert match is not None, first_field
    return tuple(match.group(1).split())


def _normalize_yaml_routes(path: Path) -> tuple[ParserRouteContract, ...]:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    executable = document["name"]
    shallow = executable.removeprefix("platform-pki-")
    leaves = document.get("commands") or (document,)
    normalized = []
    for leaf in leaves:
        route = (shallow,) if leaf is document else (shallow, leaf["name"])
        args = leaf.get("args", ())
        flags = leaf.get("flags", ())
        normalized.append(
            ParserRouteContract(
                executable,
                route,
                tuple(argument["name"] for argument in args),
                tuple(flag["long"] for flag in flags),
                tuple(
                    entry["name"] if "name" in entry else entry["long"]
                    for entry in (*args, *flags)
                    if entry.get("required") is True
                ),
                tuple((flag["long"], flag["default"]) for flag in flags if "default" in flag),
                tuple((flag["long"], tuple(flag["allowed"])) for flag in flags if "allowed" in flag),
                tuple((flag["long"], tuple(flag["conflicts"])) for flag in flags if "conflicts" in flag),
                tuple(
                    entry["name"] if "name" in entry else entry["long"]
                    for entry in (*args, *flags)
                    if entry.get("repeatable") is True
                ),
                tuple((flag["long"], flag["validate"]) for flag in flags if "validate" in flag),
            )
        )
    return tuple(normalized)


def _normalized_shell_argument(value: str) -> str:
    return re.sub(r"\$(?:\{)?([A-Za-z_][A-Za-z0-9_]*)(?:\})?", r"{\1}", value)


def _call_arguments(source: str, functions: tuple[str, ...]) -> set[str]:
    alternatives = "|".join(map(re.escape, functions))
    calls = set()
    for match in re.finditer(rf"\b(?:{alternatives})\s+(?:\"([^\"]+)\"|([A-Za-z0-9_-]+))", source):
        value = _normalized_shell_argument(match.group(1) or match.group(2))
        if value not in {"$1", "{1}", "{checkpoint}", "{checkpoint}-pending", "{checkpoint}-done", "{checkpoint}-child-failed"}:
            calls.add(value)
    return calls


def _fault_expressions(contract) -> set[str]:
    return {
        *(checkpoint for category in contract.categories for checkpoint in category.checkpoints),
        *(family.template for family in contract.dynamic_families),
    }


def _shell_words_after(source: str, function: str) -> list[list[str]]:
    calls = []
    for line in source.splitlines():
        for match in re.finditer(rf"\b{re.escape(function)}\s+", line):
            lexer = shlex.shlex(line[match.start() :], posix=True, punctuation_chars=";")
            lexer.whitespace_split = True
            words = []
            for word in lexer:
                if word == ";":
                    break
                words.append(word)
            calls.append(words)
    return calls


def _prepare_source_checkpoints(source: str) -> set[str]:
    checkpoints = _call_arguments(source, ("prepare_fault", "prepare_checkpoint"))
    for words in _shell_words_after(source, "prepare_file_destination"):
        if len(words) >= 5:
            base = _normalized_shell_argument(words[4])
            if "{checkpoint}" not in base:
                checkpoints.add(f"{base}-pending")
    for words in _shell_words_after(source, "prepare_child_failed"):
        if len(words) >= 2:
            base = _normalized_shell_argument(words[1])
            if "{checkpoint}" not in base:
                checkpoints.add(f"{base}-child-failed")
    for words in _shell_words_after(source, "prepare_copy_file"):
        if len(words) >= 6:
            base = _normalized_shell_argument(words[5])
            if "{checkpoint}" not in base:
                checkpoints.update(f"{base}-{phase}" for phase in ("pending", "done", "child-failed"))
    return checkpoints


def _literal_assignment(path: str, name: str):
    tree = ast.parse(_source(path))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == name for target in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError(f"assignment not found: {path}:{name}")


def _parametrize_rows(path: str, function_name: str) -> tuple[tuple[object, ...], ...]:
    tree = ast.parse(_source(path))
    function = next(node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == function_name)
    decorator = next(
        decorator for decorator in function.decorator_list
        if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute) and decorator.func.attr == "parametrize"
    )
    assert isinstance(decorator.args[1], (ast.Tuple, ast.List))
    rows = []
    for row in decorator.args[1].elts:
        if isinstance(row, ast.Call):
            rows.append(tuple(ast.literal_eval(argument) for argument in row.args))
        else:
            value = ast.literal_eval(row)
            rows.append(value if isinstance(value, tuple) else (value,))
    return tuple(rows)


def _make_words(name: str) -> tuple[str, ...]:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    match = re.search(rf"(?m)^{re.escape(name)} := (?P<value>.*)$", makefile)
    assert match is not None
    return tuple(match.group("value").split())


def _make_targets() -> set[str]:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    return set(re.findall(r"(?m)^([A-Za-z0-9_.-]+):", makefile))


def _function_names(path: str) -> set[str]:
    tree = ast.parse(_source(path))
    return {
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def _shell_array(source: str, symbol: str) -> tuple[str, ...]:
    match = re.search(rf"(?ms)^{re.escape(symbol)}=\((.*?)\)", source)
    assert match is not None, symbol
    return tuple(shlex.split(match.group(1)))


def _inline_shell_array(source: str, marker: str, symbol: str) -> tuple[str, ...]:
    source = source[source.index(marker) :]
    match = re.search(rf"{re.escape(symbol)}=\(([^)]*)\)", source)
    assert match is not None, symbol
    return tuple(shlex.split(match.group(1)))


def _expanded_shell_array(
    source: str,
    symbol: str,
    variable: str,
    domain_symbol: str,
) -> tuple[str, ...]:
    fields = _shell_array(source, symbol)
    domain = _shell_array(source, domain_symbol)
    match = re.search(
        rf'(?ms)^for {re.escape(variable)} in "\$\{{{re.escape(domain_symbol)}\[@\]\}}"; do\s+'
        rf'{re.escape(symbol)}\+=\((.*?)\)\s+done',
        source,
    )
    assert match is not None, symbol
    templates = shlex.split(match.group(1))
    return fields + tuple(
        template.replace(f"${{{variable}}}", value)
        for value in domain
        for template in templates
    )


def test_command_contract_inventory_is_complete_and_unique() -> None:
    assert len(PKI_COMMAND_CONTRACTS) == 18
    compatibility_names = [contract.compatibility_name for contract in PKI_COMMAND_CONTRACTS]
    unified_routes = [contract.unified_route for contract in PKI_COMMAND_CONTRACTS]
    assert len(set(compatibility_names)) == len(compatibility_names)
    assert len(set(unified_routes)) == len(unified_routes)
    assert all(name.startswith("platform-pki-") for name in compatibility_names)
    assert all(
        contract.compatibility_name.removeprefix("platform-pki-") == contract.unified_route
        for contract in PKI_COMMAND_CONTRACTS
    )


def test_python_command_map_matches_frozen_command_inventory() -> None:
    commands = _literal_assignment("src/platform_pki/compat.py", "COMMANDS")
    assert commands == {
        contract.unified_route: contract.nested_commands
        for contract in PKI_COMMAND_CONTRACTS
    }


def test_command_inventory_matches_make_and_bashly_sources() -> None:
    expected = {contract.compatibility_name for contract in PKI_COMMAND_CONTRACTS}
    maintained = {
        name
        for variable in ("SHELL_TOOLS", "PYTHON_ZIPAPPS")
        for name in _make_words(variable)
        if name.startswith("platform-pki-")
    }
    bashly = {
        definition.parents[1].name
        for definition in (ROOT / "bashly").glob("platform-pki-*/src/bashly.yml")
    }
    assert maintained == expected
    assert bashly == expected


def test_all_lock_profiles_are_ordered_prefixes() -> None:
    for contract in PKI_COMMAND_CONTRACTS:
        assert contract.lock_profiles
        for profile in contract.lock_profiles:
            assert profile == LOCK_ORDER[: len(profile)]


def test_nested_command_inventory_matches_current_command_families() -> None:
    nested = {
        contract.unified_route: contract.nested_commands
        for contract in PKI_COMMAND_CONTRACTS
        if contract.nested_commands
    }
    assert nested == {
        "certificate-export": ("publish", "resolve"),
        "csr-candidate": ("verify", "finalize", "abandon"),
        "ca-rollover": ("migrate", "status", "prepare", "recover"),
    }


def test_parser_route_inventory_exactly_matches_resolved_bashly_yaml() -> None:
    definitions = sorted((ROOT / "bashly").glob("platform-pki-*/src/bashly.yml"))
    actual = tuple(route for definition in definitions for route in _normalize_yaml_routes(definition))
    assert len(definitions) == 18
    assert len(actual) == len(PKI_PARSER_ROUTES) == 24
    assert {route.unified_route: route for route in actual} == {
        route.unified_route: route for route in PKI_PARSER_ROUTES
    }


def test_parser_routes_cover_command_and_nested_route_inventory() -> None:
    expected = set()
    for contract in PKI_COMMAND_CONTRACTS:
        if contract.nested_commands:
            expected.update((contract.unified_route, nested) for nested in contract.nested_commands)
        else:
            expected.add((contract.unified_route,))
    assert {route.unified_route for route in PKI_PARSER_ROUTES} == expected
    assert {route.compatibility_executable for route in PKI_PARSER_ROUTES} == {
        contract.compatibility_name for contract in PKI_COMMAND_CONTRACTS
    }


def test_runtime_relationships_reference_live_routes_options_and_source_guards() -> None:
    routes = {route.unified_route: route for route in PKI_PARSER_ROUTES}
    for relationship in PKI_RUNTIME_OPTION_RELATIONSHIPS:
        route = routes[relationship.route]
        names = {*route.positionals, *route.long_flags}
        assert set(relationship.fields) <= names
        source = _source(relationship.source)
        assert relationship.source_fragment in source
        assert all(field in source for field in relationship.fields)
    assert {relationship.kind for relationship in PKI_RUNTIME_OPTION_RELATIONSHIPS} == {
        "conditional-required", "conditional-conflict", "empty", "confirmation"
    }


def test_duplicate_option_inventory_exactly_matches_runtime_calls() -> None:
    for contract in PKI_DUPLICATE_OPTION_CONTRACTS:
        source = _source(contract.source)
        if contract.function == "reject_repeated_options":
            match = re.search(r"for option in ((?:--[a-z0-9-]+ ?)+); do", source)
        else:
            match = re.search(rf"(?m)^\s*{re.escape(contract.function)} ((?:--[a-z0-9-]+ ?)+)$", source)
        assert match is not None, contract
        assert tuple(match.group(1).split()) == contract.fields
    all_calls = []
    for path in sorted((ROOT / "bashly").glob("platform-pki-*/src/*command.sh")) + sorted(
        (ROOT / "bashly").glob("platform-pki-*/src/initialize.sh")
    ):
        source = path.read_text(encoding="utf-8")
        all_calls.extend(
            (path.relative_to(ROOT).as_posix(), tuple(match.group(1).split()))
            for match in re.finditer(r"(?m)^\s*pki_reject_repeated_options ((?:--[a-z0-9-]+ ?)+)$", source)
        )
    expected_calls = {
        (contract.source, contract.fields)
        for contract in PKI_DUPLICATE_OPTION_CONTRACTS
        if contract.function == "pki_reject_repeated_options"
    }
    assert set(all_calls) == expected_calls


def test_pilot_output_status_contracts_are_source_and_test_backed() -> None:
    routes = {route.unified_route for route in PKI_PARSER_ROUTES}
    scenarios = set()
    for contract in PILOT_OUTPUT_STATUS_CONTRACTS:
        assert contract.route in routes
        assert (contract.route, contract.scenario) not in scenarios
        scenarios.add((contract.route, contract.scenario))
        assert contract.stdout_kind
        assert contract.stderr_kind
        assert len({status.code for status in contract.statuses}) == len(contract.statuses)
        assert all(
            status.category in {"success", "semantic", "validation", "child-failure"}
            for status in contract.statuses
        )
        if contract.stdout_kind == "empty":
            assert contract.stdout_final_newline is None
        else:
            assert contract.stdout_final_newline is True
        if contract.stderr_kind == "optional-openssl-diagnostics-then-application-error-line":
            assert contract.stderr_final_newline is True
        else:
            assert contract.stderr_final_newline is None
        for path, fragment in contract.evidence:
            assert fragment in _source(path)
        for path, function in contract.focused_tests:
            assert function in _function_names(path)
    assert {contract.route for contract in PILOT_OUTPUT_STATUS_CONTRACTS} == {
        ("print-cert",), ("list-expiry",), ("service-verify",)
    }


def test_pilot_runtime_dependencies_are_unique_and_source_backed() -> None:
    routes = {route.unified_route for route in PKI_PARSER_ROUTES}
    keys = []
    for contract in PILOT_RUNTIME_DEPENDENCY_CONTRACTS:
        assert contract.route in routes
        assert contract.requirement in {"required", "conditional", "optional-evidence"}
        assert contract.condition
        assert contract.capability
        assert contract.source_fragment in _source(contract.source)
        keys.append((contract.route, contract.program))
    assert len(keys) == len(set(keys))


def test_pilot_installed_assets_are_source_and_test_backed() -> None:
    pilot_routes = {("print-cert",), ("list-expiry",), ("service-verify",)}
    paths = []
    for contract in PILOT_INSTALLED_ASSET_CONTRACTS:
        paths.append(contract.path)
        assert contract.mode == 0o644
        assert set(contract.consumers) == pilot_routes
        assert contract.required_phase == "operational-only"
        assert contract.lookup_order == (
            "PLATFORM_TOOLS_LIB_DIR",
            "checkout-relative",
            "PLATFORM_TOOLS_SHARE_DIR-or-XDG-user-share",
        )
        for path, fragment in contract.evidence:
            assert fragment in _source(path)
        for path, function in contract.focused_tests:
            assert function in _function_names(path)
    assert paths == ["lib/platform-pki-common.sh"]


def test_every_command_has_focused_verification() -> None:
    make_targets = _make_targets()
    for contract in PKI_COMMAND_CONTRACTS:
        assert contract.test_targets
        assert all(target.startswith("test-") for target in contract.test_targets)
        assert set(contract.test_targets) <= make_targets


def test_persisted_and_recovery_contract_names_are_unique() -> None:
    record_names = [contract.name for contract in PERSISTED_RECORD_CONTRACTS]
    recovery_names = [contract.name for contract in RECOVERY_CONTRACTS]
    assert len(set(record_names)) == len(record_names)
    assert len(set(recovery_names)) == len(recovery_names)
    assert {contract.operation for contract in RECOVERY_CONTRACTS} == {
        "root-bootstrap",
        "intermediate-bootstrap",
        "csr-sign",
        "csr-finalize",
        "legacy-migrate",
        "rollover-prepare",
    }


def test_declared_record_fields_exactly_match_authoritative_sources() -> None:
    for contract in PERSISTED_RECORD_CONTRACTS:
        if contract.fields is None:
            continue
        if contract.ordering.startswith(("literal ", "C-locale ")):
            continue
        source = _source(contract.source)
        if contract.ordering == "PKI_CSR_JOURNAL_FIELDS":
            actual = _expanded_shell_array(
                source,
                contract.ordering,
                "pki_csr_key",
                "PKI_CSR_DB_KEYS",
            )
        elif contract.ordering == "PKI_CANDIDATE_JOURNAL_FIELDS":
            actual = _expanded_shell_array(
                source,
                contract.ordering,
                "pki_candidate_source_key",
                "PKI_CANDIDATE_SOURCE_KEYS",
            )
        else:
            actual = _shell_array(source, contract.ordering)
        assert actual == contract.fields, contract.name
        assert actual[0] == "schema"
        assert len(actual) == len(set(actual))


def test_all_record_contracts_declare_unique_fields_and_valid_schema() -> None:
    assert len(PERSISTED_RECORD_CONTRACTS) == 24
    for contract in PERSISTED_RECORD_CONTRACTS:
        assert contract.fields
        assert len(contract.fields) == len(set(contract.fields))
        if contract.schema is not None:
            assert "schema" in contract.fields
            if not contract.ordering.startswith("C-locale "):
                assert contract.fields[0] == "schema"


@pytest.mark.parametrize(
    ("fields", "schema", "count"),
    (
        (ACTIVE_ISSUER_FIELDS, None, 2),
        (GENERATION_RESERVATION_TRANSACTION_FIELDS, None, 4),
        (GENERATION_RESERVATION_BOOTSTRAP_CONSUMED_FIELDS, None, 5),
        (GENERATION_RESERVATION_MIGRATION_FIELDS, None, 5),
        (BACKUP_RECEIPT_FIELDS, 2, 14),
        (ROOT_BOOTSTRAP_JOURNAL_FIELDS, 3, 20),
        (ROOT_BOOTSTRAP_RECOVERY_FIELDS, 3, 20),
        (INTERMEDIATE_BOOTSTRAP_JOURNAL_FIELDS, 3, 56),
        (INTERMEDIATE_BOOTSTRAP_RECOVERY_FIELDS, 3, 56),
        (LEGACY_MIGRATION_JOURNAL_FIELDS, 2, 56),
        (LEGACY_MIGRATION_RECOVERY_FIELDS, 2, 56),
        (LEGACY_MIGRATION_CHECKPOINT_FIELDS, 2, 58),
        (ROLLOVER_PREPARE_JOURNAL_FIELDS, 5, 206),
        (ROLLOVER_PREPARED_MANIFEST_FIELDS, 1, 20),
    ),
)
def test_declared_record_shapes_serialize_with_one_final_newline(fields, schema, count) -> None:
    values = {field: f"value-{index}" for index, field in enumerate(fields)}
    if schema is not None:
        values["schema"] = str(schema)

    payload = "".join(f"{field}={values[field]}\n" for field in fields).encode()

    assert len(fields) == count
    assert payload.endswith(b"\n")
    assert not payload.endswith(b"\n\n")
    assert payload.count(b"\n") == count
    assert tuple(line.partition(b"=")[0].decode() for line in payload.splitlines()) == fields
    if schema is not None:
        assert payload.splitlines()[fields.index("schema")] == f"schema={schema}".encode()


def test_literal_record_orders_match_bash_writers() -> None:
    cases = (
        (
            "lib/platform-pki-common.sh",
            'pki_atomic_write "$(pki_active_issuer_manifest)" "',
            '\n"',
            ACTIVE_ISSUER_FIELDS,
            None,
        ),
        (
            "lib/platform-pki-common.sh",
            'pki_atomic_write "$(pki_service_issuer "$service")" "',
            '\n"',
            ACTIVE_ISSUER_FIELDS,
            None,
        ),
        (
            "bashly/platform-pki-root-create/src/root_command.sh",
            'pki_atomic_write "$TXN_DIR/reservation-consumed" "',
            '\n";',
            GENERATION_RESERVATION_BOOTSTRAP_CONSUMED_FIELDS,
            None,
        ),
        (
            "bashly/platform-pki-ca-rollover/src/prepare_command.sh",
            'pki_atomic_write "$TXN_DIR/$kind-reserved" "',
            '\n";',
            GENERATION_RESERVATION_TRANSACTION_FIELDS,
            None,
        ),
        (
            "bashly/platform-pki-ca-rollover/src/migrate_command.sh",
            'pki_atomic_write "$TXN_DIR/root-reserved.publish" "',
            '\n";',
            GENERATION_RESERVATION_MIGRATION_FIELDS,
            None,
        ),
        (
            "bashly/platform-pki-backup/src/root_command.sh",
            'pki_atomic_write "$receipt" "',
            '\n"',
            BACKUP_RECEIPT_FIELDS,
            2,
        ),
        (
            "bashly/platform-pki-root-create/src/root_command.sh",
            'pki_write_journal "$JOURNAL" "',
            '\n"',
            ROOT_BOOTSTRAP_JOURNAL_FIELDS,
            3,
        ),
        (
            "bashly/platform-pki-ca-rollover/src/migrate_command.sh",
            'pki_write_journal "$JOURNAL" "',
            '\n"',
            LEGACY_MIGRATION_JOURNAL_FIELDS,
            2,
        ),
        (
            "bashly/platform-pki-ca-rollover/src/prepare_command.sh",
            'cat >"$LONG_STAGE/manifest" <<EOF\n',
            "\nEOF",
            ROLLOVER_PREPARED_MANIFEST_FIELDS,
            1,
        ),
    )
    for path, start, end, expected, schema in cases:
        block = _source_record_block(path, start, end)
        assert _record_fields(block) == expected
        schema_match = re.search(r"(?m)^schema=([^\n]+)$", block)
        if schema is None:
            assert schema_match is None
        else:
            assert schema_match is not None
            assert schema_match.group(1) == str(schema)


def test_every_generation_reservation_writer_matches_a_declared_variant() -> None:
    transaction = GENERATION_RESERVATION_TRANSACTION_FIELDS
    consumed = GENERATION_RESERVATION_BOOTSTRAP_CONSUMED_FIELDS
    migration = GENERATION_RESERVATION_MIGRATION_FIELDS
    expected = {
        "bashly/platform-pki-root-create/src/root_command.sh": (
            transaction, transaction, consumed,
        ),
        "bashly/platform-pki-intermediate-create/src/root_command.sh": (
            transaction, transaction, consumed,
        ),
        "bashly/platform-pki-ca-rollover/src/prepare_command.sh": (transaction,) * 6,
        "bashly/platform-pki-ca-rollover/src/migrate_command.sh": (migration,) * 6,
    }
    actual = {}
    source_paths = (
        *(ROOT / "bashly").rglob("*.sh"),
        *(ROOT / "lib").glob("*.sh"),
    )
    for path in source_paths:
        relative = path.relative_to(ROOT).as_posix()
        records = _generation_record_fields(relative)
        if records:
            actual[relative] = records
    assert actual == expected


def test_record_discovery_accepts_nested_destination_quotes() -> None:
    source = '''pki_atomic_write "$(pki_generation_reservation "$id")" "generation=$id
kind=root
status=reserved
transaction=$transaction
"'''
    assert _record_fields_after_atomic_write(source, "generation") == (
        GENERATION_RESERVATION_TRANSACTION_FIELDS,
    )


def test_all_direct_issuer_pair_writers_match_the_shared_contract() -> None:
    assert _record_fields_after_atomic_write(
        _source("lib/platform-pki-common.sh"),
        "root",
    ) == (ACTIVE_ISSUER_FIELDS, ACTIVE_ISSUER_FIELDS)
    assert _record_fields_after_atomic_write(
        _source("bashly/platform-pki-ca-rollover/src/migrate_command.sh"),
        "root",
    ) == (ACTIVE_ISSUER_FIELDS, ACTIVE_ISSUER_FIELDS)


def test_intermediate_bootstrap_writer_matches_grouped_contract() -> None:
    source = _source("bashly/platform-pki-intermediate-create/src/root_command.sh")
    block = _source_record_block(
        "bashly/platform-pki-intermediate-create/src/root_command.sh",
        'pki_write_journal "$JOURNAL" "',
        '\n"',
    )
    assert _record_fields(block) == INTERMEDIATE_BOOTSTRAP_PREFIX_FIELDS + ("committed",)
    assert re.search(r"(?m)^schema=3$", block)
    assert INTERMEDIATE_BOOTSTRAP_JOURNAL_FIELDS == (
        INTERMEDIATE_BOOTSTRAP_PREFIX_FIELDS
        + INTERMEDIATE_BOOTSTRAP_DB_FIELDS
        + ("committed",)
    )
    for fragment in (
        'ROOT_DB_KEYS=(index index_attr serial crlnumber index_old index_attr_old serial_old crlnumber_old newcert)',
        'db_fields+="root_${key}_pre_identity=${ROOT_DB_PRE[$key]}',
        'root_${key}_post_identity=${ROOT_DB_POST[$key]}',
        'root_${key}_backup_identity=${ROOT_DB_BACKUP_ID[$key]}',
    ):
        assert fragment in source


def test_recovery_record_variants_use_c_locale_sorted_order() -> None:
    source = _source("bashly/platform-pki-ca-rollover/src/recover_command.sh")
    bootstrap_common = _literal_for_fields(
        source,
        "schema operation transaction phase stage_dir",
    )
    root_specific = _literal_for_fields(
        source,
        "generation authority_dir authority_identity bootstrap_identity",
    )
    intermediate_specific = _literal_for_fields(
        source,
        "root_generation intermediate_generation root_dir",
    )
    db_keys = _inline_shell_array(source, "declare -A db_path=()", "db_keys")
    intermediate_source = source[source.index("declare -A db_path=()") :]
    suffix_match = re.search(r"for suffix in ([a-z_ ]+); do field=", intermediate_source)
    assert suffix_match is not None
    db_suffixes = tuple(suffix_match.group(1).split())
    intermediate_db_fields = tuple(
        f"root_{key}_{suffix}"
        for key in db_keys
        for suffix in db_suffixes
    )
    assert ROOT_BOOTSTRAP_RECOVERY_FIELDS == tuple(sorted(
        (*bootstrap_common, *root_specific, "reservation_identity")
    ))
    assert INTERMEDIATE_BOOTSTRAP_RECOVERY_FIELDS == tuple(sorted(
        (*bootstrap_common, *intermediate_specific, *intermediate_db_fields, "reservation_identity")
    ))
    legacy_required = _inline_shell_array(
        source,
        "required_fields=(schema operation transaction phase legacy_root",
        "required_fields",
    )
    assert LEGACY_MIGRATION_RECOVERY_FIELDS == tuple(sorted(legacy_required))
    assert LEGACY_MIGRATION_CHECKPOINT_FIELDS == tuple(
        sorted((*legacy_required, "recovery_action", "recovery_step"))
    )
    for fragment in (
        'done < <(printf \'%s\\n\' "${!PKI_RECORD[@]}" | LC_ALL=C sort)',
        'PKI_RECORD[reservation_identity]=${PKI_RECORD[reservation_abandoned_identity]}',
        'PKI_RECORD[recovery_action]=$ACTION',
        'PKI_RECORD[recovery_step]=$1',
    ):
        assert fragment in source


def test_rollover_prepare_journal_matches_source_groups_and_sorting() -> None:
    recovery = _source("bashly/platform-pki-ca-rollover/src/recover_command.sh")
    assert _inline_shell_array(
        recovery,
        'if [[ ${PKI_RECORD[operation]:-} == rollover-prepare ]]',
        "required_fields",
    ) == ROLLOVER_PREPARE_BASE_FIELDS

    prepare = _source("bashly/platform-pki-ca-rollover/src/prepare_command.sh")
    declaration_match = re.search(r"declare -A PREP=\((.*?)\)\n", prepare, re.DOTALL)
    assert declaration_match is not None
    declaration = declaration_match.group(1)
    assert "[schema]=5" in declaration
    declaration_fields = set(re.findall(r"\[([a-z][a-z0-9_]*)\]=", declaration))
    literal_fields = set(re.findall(r"PREP\[([a-z][a-z0-9_]*)\]", prepare))
    assert declaration_fields | literal_fields == set(ROLLOVER_PREPARE_BASE_FIELDS)

    root_keys = _shell_array(prepare, "ROOT_DB_KEYS")
    assert root_keys == ROOT_DB_KEYS
    root_loop = re.search(
        r'for key in "\$\{ROOT_DB_KEYS\[@\]\}"; do (.*?); done',
        prepare,
        re.DOTALL,
    )
    assert root_loop is not None
    root_templates = re.findall(r"PREP\[([^]]*\$\{key\}[^]]*)\]", root_loop.group(1))
    root_fields = tuple(
        template.replace("${key}", key)
        for key in root_keys
        for template in root_templates
    )
    assert root_fields == ROLLOVER_PREPARE_ROOT_DB_FIELDS

    prepartial_loop = re.search(
        r"for key in (trust_snapshot .*?); do (.*?); done",
        prepare,
        re.DOTALL,
    )
    assert prepartial_loop is not None
    prepartial_names = tuple(shlex.split(prepartial_loop.group(1)))
    prepartial_templates = re.findall(
        r"PREP\[([^]]*\$\{key\}[^]]*)\]",
        prepartial_loop.group(2),
    )
    prepartial_fields = tuple(
        template.replace("${key}", key)
        for key in prepartial_names
        for template in prepartial_templates
    )
    assert prepartial_names == ROLLOVER_PREPARE_PREPARTIAL_NAMES
    assert prepartial_fields == ROLLOVER_PREPARE_PREPARTIAL_FIELDS

    helper_fields = set()
    for function, field_position in (
        ("prepare_file_destination", 2),
        ("prepare_copy_file", 3),
        ("prepare_child_failed", 2),
    ):
        for words in _shell_words_after(prepare, function):
            if len(words) > field_position and "$" not in words[field_position]:
                helper_fields.add(words[field_position])
    for loop in re.finditer(r"for spec in (.*?); do(.*?)done", prepare, re.DOTALL):
        if "prepare_copy_file" not in loop.group(2):
            continue
        calls = _shell_words_after(loop.group(2), "prepare_copy_file")
        for spec in shlex.split(loop.group(1)):
            key = spec.split(":", 1)[1]
            for words in calls:
                helper_fields.add(
                    words[3].replace("${key}", key).replace("$key", key)
                )
    assert helper_fields == set(ROLLOVER_PREPARE_PREPARTIAL_NAMES)

    failure_loop = next(
        loop
        for loop in re.finditer(r"for spec in (.*?); do(.*?)done", prepare, re.DOTALL)
        if "PREP[${key}_partial_identity]" in loop.group(2)
    )
    failure_fields = {
        f"{spec.split(':', 1)[0]}_partial_identity"
        for spec in shlex.split(failure_loop.group(1))
    }
    expected_failure_fields = {
        "candidate_intermediate_cert_partial_identity",
        *(f"signing_{key}_partial_identity" for key in ROOT_DB_KEYS),
    }
    assert failure_fields == expected_failure_fields
    assert failure_fields <= set(ROLLOVER_PREPARE_JOURNAL_FIELDS)

    dynamic_templates = set(re.findall(r"PREP\[([^]]*\$[^]]*)\]", prepare))
    assert dynamic_templates == {
        "$key",
        "${field}_identity",
        "${field}_partial_identity",
        "${field}_pre_identity",
        "${key}_partial_identity",
        "${key}_pre_identity",
        "${kind}_reservation_abandoned_identity",
        "${kind}_reservation_consumed_identity",
        "${kind}_reservation_reserved_identity",
        "root_${key}_backup_identity",
        "root_${key}_post_identity",
        "root_${key}_pre_identity",
        "root_${key}_rollback_identity",
        "root_${key}_source_identity",
        "signing_${key}_partial_identity",
        "signing_${key}_pre_identity",
        "signing_${key}_was_absent",
    }
    source_fields = declaration_fields | literal_fields | set(root_fields) | set(prepartial_fields)
    assert ROLLOVER_PREPARE_JOURNAL_FIELDS == tuple(sorted(source_fields))
    assert 'done < <(printf \'%s\\n\' "${!PREP[@]}" | LC_ALL=C sort)' in prepare


def test_atomic_state_writer_canonicalizes_to_one_final_newline() -> None:
    source = _source("lib/platform-pki-common.sh")
    for fragment in (
        'while IFS= read -r line || [[ -n $line ]]; do',
        '[[ -n $line ]] || continue',
        'printf \'%s\\n\' "$line" >>"$tmp"',
        'done < <(printf \'%s\' "$content")',
    ):
        assert fragment in source


def test_certificate_export_duplicate_record_declarations_match_candidate_library() -> None:
    export = _source("bashly/platform-pki-certificate-export/src/initialize.sh")
    candidate = _source("lib/platform-pki-csr-candidate.sh")
    assert _shell_array(export, "PKI_CERTIFICATE_EXPORT_RESPONSE_FIELDS") == _shell_array(
        candidate, "PKI_CANDIDATE_RESPONSE_FIELDS"
    )
    assert _shell_array(export, "PKI_CERTIFICATE_EXPORT_CANDIDATE_FIELDS") == _shell_array(
        candidate, "PKI_CANDIDATE_RECORD_FIELDS"
    )
    assert _shell_array(export, "PKI_CERTIFICATE_EXPORT_ARTIFACT_FIELDS") == _shell_array(
        candidate, "PKI_CANDIDATE_ARTIFACT_FIELDS"
    )


def test_recovery_contracts_match_authoritative_sources() -> None:
    recovery_routes = {
        "platform-pki csr-recover": "bashly/platform-pki-csr-recover/src/root_command.sh",
        "platform-pki ca-rollover recover": "bashly/platform-pki-ca-rollover/src/recover_command.sh",
    }
    for contract in RECOVERY_CONTRACTS:
        source = (ROOT / contract.checkpoint_source).read_text(encoding="utf-8")
        assert contract.operation in source
        assert re.search(rf"schema[^\n]*{contract.schema}", source)
        route_source = recovery_routes[contract.compatibility_recovery]
        labels = [label for label, _path, _fragment in contract.recovery_evidence]
        assert labels.count("route") == 1
        assert set(labels) - {"route"} == set(contract.allowed_recovery_actions)
        assert any(
            label == "route" and path == route_source
            for label, path, _fragment in contract.recovery_evidence
        )
        for _label, path, fragment in contract.recovery_evidence:
            assert fragment in _source(path)


def test_literal_and_finite_writer_fault_hooks_match_authoritative_sources() -> None:
    contracts = {contract.name: contract for contract in FAULT_HOOK_CONTRACTS}
    for name in (
        "root bootstrap writer", "intermediate bootstrap writer", "CSR signing writer",
        "candidate finalization writer", "legacy migration writer",
    ):
        contract = contracts[name]
        source = _source(contract.source)
        functions = (contract.hook,)
        if name == "CSR signing writer":
            functions += ("pki_csr_checkpoint",)
        actual = _call_arguments(source, functions)
        assert actual == _fault_expressions(contract)
        assert all(variable in source for variable in contract.fault_variables)


def test_rollover_prepare_fault_hooks_and_helper_domains_match_source() -> None:
    contract = next(contract for contract in FAULT_HOOK_CONTRACTS if contract.name == "rollover preparation writer")
    source = _source(contract.source)
    assert _prepare_source_checkpoints(source) == _fault_expressions(contract)
    assert all(variable in source for variable in contract.fault_variables)
    for family in contract.dynamic_families:
        assert family.source_declaration in source
        assert family.domain


def test_rollover_recovery_fault_hooks_and_dynamic_domains_match_source() -> None:
    contract = next(contract for contract in FAULT_HOOK_CONTRACTS if contract.name == "rollover recovery")
    source = _source(contract.source)
    actual = _call_arguments(source, ("recover_fault", "checkpoint_recovery", "migration_checkpoint"))
    assert actual == _fault_expressions(contract)
    assert all(variable in source for variable in contract.fault_variables)
    for family in contract.dynamic_families:
        assert family.source_declaration in source
        assert bool(family.domain) != family.runtime_derived
    assert {family.template for family in contract.dynamic_families if family.runtime_derived} == {
        "rollback-issuer-{service}-pending", "rollback-issuer-{service}-done",
        "resume-issuer-{service}-pending", "resume-issuer-{service}-done",
    }


def test_checkpoint_source_domains_match_shell_declarations() -> None:
    csr_source = _source("lib/platform-pki-csr-sign.sh")
    intermediate_source = _source("bashly/platform-pki-intermediate-create/src/root_command.sh")
    prepare_source = _source("bashly/platform-pki-ca-rollover/src/prepare_command.sh")
    csr_match = re.search(r"PKI_CSR_DB_KEYS=\(([^)]+)\)", csr_source)
    intermediate_match = re.search(r"ROOT_DB_KEYS=\(([^)]+)\)", intermediate_source)
    prepare_match = re.search(r"ROOT_DB_KEYS=\(([^)]+)\)", prepare_source)
    assert csr_match is not None and tuple(csr_match.group(1).split()) == CSR_DB_KEYS
    assert intermediate_match is not None and tuple(intermediate_match.group(1).split()) == ROOT_DB_KEYS
    assert prepare_match is not None and tuple(prepare_match.group(1).split()) == ROOT_DB_KEYS
    quarantine = re.search(r"basename =~ \^\(([^)]+)\)\$", _source("bashly/platform-pki-ca-rollover/src/recover_command.sh"))
    assert quarantine is not None
    assert tuple(value.replace("\\.", ".") for value in quarantine.group(1).split("|")) == MIGRATION_QUARANTINE_NAMES


def test_maintained_pytest_writer_checkpoint_domains_are_covered() -> None:
    contracts = {contract.name: contract for contract in FAULT_HOOK_CONTRACTS}
    root = contracts["root bootstrap writer"]
    assert set(_literal_assignment("tests/pki/test_root_create.py", "ROOT_BOUNDARIES")) == set(root.categories[0].checkpoints)

    intermediate = contracts["intermediate bootstrap writer"]
    assert _literal_assignment("tests/pki/test_intermediate_create.py", "BOUNDARIES") == (
        "after-journal", "after-reservation", "after-intermediate", "after-root-db",
        "after-reservation-consumed", "after-active", "after-bootstrap",
    )
    assert set(_literal_assignment("tests/pki/test_intermediate_create.py", "BOUNDARIES")) < _fault_expressions(intermediate)

    csr_rows = _parametrize_rows("tests/pki/test_csr_signing.py", "test_interrupted_signing_has_deterministic_recovery")
    csr = contracts["CSR signing writer"]
    expanded_csr = _fault_expressions(csr)
    for family in csr.dynamic_families:
        expanded_csr.update(family.template.format(**{family.variable: value}) for value in family.domain)
    assert {row[0] for row in csr_rows} <= expanded_csr
    categories = {checkpoint: category.name for category in csr.categories for checkpoint in category.checkpoints}
    for family in csr.dynamic_families:
        categories.update({family.template.format(**{family.variable: value}): family.category for value in family.domain})
    assert all((categories[str(row[0])] == "post-commit") is row[1] for row in csr_rows)

    candidate_rows = _parametrize_rows("tests/pki/test_csr_candidate.py", "test_finalize_recovery_resumes_outcome_and_active_pointer")
    assert tuple(row[0] for row in candidate_rows) == contracts["candidate finalization writer"].categories[0].checkpoints

    migration_pairs = _literal_assignment("tests/pki/test_ca_rollover_migrate.py", "MIGRATION_FAILURE_BOUNDARIES")
    migration_tested = {"after-journal", *(pair[0] for pair in migration_pairs)}
    assert migration_tested == _fault_expressions(contracts["legacy migration writer"])


def test_maintained_rollover_checkpoint_domains_are_source_inventory_subsets() -> None:
    prepare = next(contract for contract in FAULT_HOOK_CONTRACTS if contract.name == "rollover preparation writer")
    expanded_prepare = _fault_expressions(prepare)
    for family in prepare.dynamic_families:
        expanded_prepare.update(family.template.format(**{family.variable: value}) for value in family.domain)
    for constant in ("INTERMEDIATE_EARLY_CHECKPOINTS", "ROOT_CRYPTO_CHECKPOINTS"):
        assert set(_literal_assignment("tests/pki/test_ca_rollover_prepare_recovery.py", constant)) <= expanded_prepare

    recovery = next(contract for contract in FAULT_HOOK_CONTRACTS if contract.name == "rollover recovery")
    expanded_recovery = _fault_expressions(recovery)
    for family in recovery.dynamic_families:
        if not family.runtime_derived:
            expanded_recovery.update(family.template.format(**{family.variable: value}) for value in family.domain)
        else:
            expanded_recovery.add(family.template.format(**{family.variable: "app"}))
    migration_source = "tests/pki/test_ca_rollover_migrate.py"
    for constant in ("MIGRATION_ROLLBACK_RECOVERY_BOUNDARIES", "MIGRATION_RESUME_RECOVERY_BOUNDARIES"):
        for base in _literal_assignment(migration_source, constant):
            assert {f"{base}-pending", f"{base}-done"} <= expanded_recovery
    advanced_source = "tests/pki/test_ca_rollover_recovery_advanced.py"
    assert set(_literal_assignment(advanced_source, "TERMINAL_CHECKPOINTS")) <= expanded_recovery
    for constant in ("INTERMEDIATE_RECOVERY_BOUNDARIES", "ROOT_RESUME_RECOVERY_BOUNDARIES", "ROOT_ROLLBACK_RECOVERY_BOUNDARIES"):
        for base in _literal_assignment(advanced_source, constant):
            assert {f"{base}-pending", f"{base}-done"} <= expanded_recovery
