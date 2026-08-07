import ast
import re
import shlex
from pathlib import Path

import pytest
import yaml

from .migration_contract import (
    CSR_DB_KEYS,
    FAULT_HOOK_CONTRACTS,
    LOCK_ORDER,
    MIGRATION_QUARANTINE_NAMES,
    PERSISTED_RECORD_CONTRACTS,
    PKI_COMMAND_CONTRACTS,
    PKI_DUPLICATE_OPTION_CONTRACTS,
    PKI_PARSER_ROUTES,
    PKI_RUNTIME_OPTION_RELATIONSHIPS,
    RECOVERY_CONTRACTS,
    ROOT_DB_KEYS,
    ParserRouteContract,
)


pytestmark = pytest.mark.infrastructure
ROOT = Path(__file__).parents[2]


def _source(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


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


def _shell_array(source: str, symbol: str) -> tuple[str, ...]:
    match = re.search(rf"(?ms)^{re.escape(symbol)}=\((.*?)\)", source)
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


def test_command_inventory_matches_make_and_bashly_sources() -> None:
    expected = {contract.compatibility_name for contract in PKI_COMMAND_CONTRACTS}
    maintained = {name for name in _make_words("SHELL_TOOLS") if name.startswith("platform-pki-")}
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
