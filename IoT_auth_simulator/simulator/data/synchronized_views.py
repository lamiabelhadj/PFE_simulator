"""Separated synchronized dataset views with C1.7 validation integration."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

import pandas as pd

from simulator.anomaly_contract import SYNCHRONIZED_GENERATION_PROFILE
from simulator.config.settings import cfg
from simulator.data.dataset_contract import (
    FIELD_MANIFEST_VERSION,
    dataset_capability_manifest,
    field_manifest,
    field_names_for_view,
    historical_feature_contract,
)
from simulator.engines.event_engine import SessionContext
from simulator.event_model import AuthEvent
from simulator.provenance import GenerationProvenance, build_generation_provenance
from simulator.validation import ValidationReport, validate_synchronized_dataset


SequencePairs = list[tuple[list[AuthEvent], SessionContext]]


def _require_synchronized_profiles(sequences: SequencePairs) -> None:
    incompatible = sorted({
        context.generation_profile for _, context in sequences
        if context.generation_profile != SYNCHRONIZED_GENERATION_PROFILE
    })
    if incompatible:
        raise ValueError(
            "synchronized exports reject historical generation profiles: "
            + ", ".join(incompatible)
        )


def _observed_time(event: AuthEvent) -> float:
    return float(event.observed_timestamp if event.observed_timestamp is not None else event.timestamp)


def to_detector_observation_df(sequences: SequencePairs) -> pd.DataFrame:
    """Return only legitimate observed evidence; no IDs, GT, debug, or provenance."""
    _require_synchronized_profiles(sequences)
    rows: list[dict[str, Any]] = []
    for events, _context in sequences:
        previous_observed: Optional[float] = None
        for event in events:
            observed = _observed_time(event)
            delay = 0.0 if previous_observed is None else observed - previous_observed
            rows.append({
                "event_type": event.event_type.value,
                "observed_timestamp": round(observed, 6),
                "observed_delay_since_previous_event": round(delay, 6),
                "result": event.result.value,
                "failure_reason": event.failure_reason,
                "retry_count": event.retry_count,
                "token_id": event.token_id,
                "nonce": event.nonce,
                "topic": event.topic,
                "resource_id": event.resource_id,
                "requested_action": event.requested_action,
            })
            previous_observed = observed
    return pd.DataFrame(rows, columns=field_names_for_view("detector_observations"))


def to_ground_truth_views(
    sequences: SequencePairs,
    validation: Optional[ValidationReport] = None,
) -> dict[str, list[dict[str, Any]]]:
    _require_synchronized_profiles(sequences)
    event_rows: list[dict[str, Any]] = []
    trace_rows: list[dict[str, Any]] = []
    ordinal = 0
    for events, context in sequences:
        records = list(context.injection_records)
        record_by_id = {record.get("injection_id"): record for record in records}
        for event in events:
            record = record_by_id.get(event.injection_id)
            event_rows.append({
                "event_id": event.event_id,
                "event_ordinal": ordinal,
                "anomaly_label": event.anomaly_label,
                "anomaly_variant_name": event.anomaly_variant_name,
                "invariant_families": list(event.invariant_families),
                "observable_violation_candidate": bool(
                    record and record.get("observable_violation_candidate", False)
                ),
                "validation_status": (
                    validation.event_ground_truth_statuses.get(event.event_id)
                    if validation else (
                        record.get("validation_status") if record
                        else "validation_not_run"
                    )
                ),
            })
            ordinal += 1
        trace_rows.append({
            "trace_id": context.trace_id,
            "observable_anomaly": bool(context.observable_anomaly),
            "observable_violation_candidate": bool(context.observable_violation_candidate),
            "anomaly_variants": sorted({
                record.get("anomaly_variant_name") for record in records
                if record.get("anomaly_variant_name")
            }),
            "invariant_families": sorted({
                family for record in records
                for family in record.get("invariant_families", ())
            }),
            "validation_statuses": [
                validation.trace_ground_truth_statuses.get(
                    context.trace_id, "validation_failed"
                )
            ] if validation else ["validation_not_run"],
            "hard_negative_status": "not_implemented",
        })
    return {"events": event_rows, "traces": trace_rows}


def to_provenance_view(
    sequences: SequencePairs,
    provenance: GenerationProvenance,
) -> dict[str, Any]:
    _require_synchronized_profiles(sequences)
    traces: list[dict[str, Any]] = []
    events_out: list[dict[str, Any]] = []
    observation_row = 0
    for events, context in sequences:
        traces.append({
            "run_id": provenance.run_id,
            "trace_id": context.trace_id,
            "scenario_id": context.scenario_id,
            "device_id": context.device_id,
            "legacy_session_id": context.legacy_session_id,
            "protected_session_id": context.protected_session_id,
            "auth_attempt_ids": list(context.auth_attempt_ids),
            "generation_profile": context.generation_profile,
            "scenario_family": context.attack_type,
            "scenario_intent": bool(context.attack_scenario_intent),
            "attack_phase": context.attack_phase,
            "generator_severity": context.severity,
            "injection_records": list(context.injection_records),
        })
        for event in events:
            events_out.append({
                "observation_row": observation_row,
                "event_id": event.event_id,
                "trace_id": event.trace_id,
                "scenario_id": event.scenario_id,
                "device_id": event.device_id,
                "gateway_id": event.gateway_id,
                "auth_server_id": event.auth_server_id,
                "broker_id": event.broker_id,
                "legacy_session_id": event.session_id,
                "protected_session_id": event.protected_session_id,
                "auth_attempt_id": event.auth_attempt_id,
                "access_request_id": event.access_request_id,
                "injection_id": event.injection_id,
            })
            observation_row += 1
    capabilities = dataset_capability_manifest(
        provenance,
        generation_profiles=(context.generation_profile for _, context in sequences),
    )
    simulation_config = provenance.configuration_snapshot.get("simulation", {})
    return {
        "dataset": {
            "generation": provenance.to_dict(),
            "capabilities": capabilities,
            "field_manifest_version": FIELD_MANIFEST_VERSION,
            "row_alignment": (
                "provenance.events.observation_row maps to zero-based row order in detector_observations"
            ),
            "randomness_metadata": {
                "master_seed": simulation_config.get("random_seed"),
                "stream_model": "single_python_random_stream",
                "derived_stream_metadata_available": False,
            },
        },
        "traces": traces,
        "events": events_out,
    }


def to_debug_view(sequences: SequencePairs) -> dict[str, list[dict[str, Any]]]:
    _require_synchronized_profiles(sequences)
    event_rows: list[dict[str, Any]] = []
    trace_rows: list[dict[str, Any]] = []
    for events, context in sequences:
        for event in events:
            event_rows.append({
                "event_id": event.event_id,
                "semantic_timestamp": round(event.timestamp, 6),
                "observed_timestamp_source": event.observed_timestamp_source,
                "targeted_temporal_relationship": event.targeted_temporal_relationship,
                "previous_state": event.previous_state.value,
                "new_state": event.new_state.value,
                "authenticated_identity": event.authenticated_identity,
                "token_validation_result": event.token_validation_result,
                "authorization_decision": event.authorization_decision,
                "resource_operation_outcome": event.resource_operation_outcome,
                "authenticated_context_active": event.authenticated_context_active,
                "token_context_active": event.token_context_active,
                "protected_session_active": event.protected_session_active,
                "source_context": event.source_context,
                "token_expiry": event.token_expiry,
                "token_scope": event.token_scope,
            })
        trace_rows.append({
            "trace_id": context.trace_id,
            "semantic_time_context": {
                "semantic_time_domain": context.semantic_time_domain,
                "trace_started_at": context.trace_started_at,
                "trace_ended_at": context.trace_ended_at,
                "token_issued_at": context.token_issued_at,
                "token_presented_at": context.token_presented_at,
                "token_validation_at": context.token_validation_at,
                "token_validity_duration_s": context.token_validity_duration_s,
                "challenge_issued_at": context.challenge_issued_at,
                "challenge_response_at": context.challenge_response_at,
                "protected_session_started_at": context.protected_session_started_at,
                "protected_session_ended_at": context.protected_session_ended_at,
                "renewal_requested_at": context.renewal_requested_at,
                "renewed_token_issued_at": context.renewed_token_issued_at,
            },
            "security_decision_context": {
                "authenticated_identity": context.authenticated_identity,
                "authenticated_context_active": context.authenticated_context_active,
                "token_validation_result": context.token_validation_result,
                "token_context_active": context.token_context_active,
                "protected_session_active": context.protected_session_active,
                "authorization_decision": context.authorization_decision,
                "resource_operation_outcome": context.resource_operation_outcome,
            },
            "experimental_scores": {
                "trust_score": context.trust_score,
                "behavior_deviation_score": context.behavior_deviation_score,
                "gateway_decision": context.gateway_decision,
            },
            "privileged_generator_flags": {
                "replay_window_violation": context.replay_window_violation,
                "topic_scope_violation": context.topic_scope_violation,
                "source_ip_change": context.source_ip_change,
                "identity_claim_mismatch": context.identity_claim_mismatch,
                "token_device_mismatch": context.token_device_mismatch,
                "unauthorized_access_attempt": context.unauthorized_access_attempt,
                "token_age_at_replay": context.token_age_at_replay,
                "nonce_age_at_reuse": context.nonce_age_at_reuse,
                "timestamp_delta_s": context.timestamp_delta_s,
                "duplicate_session_count": context.duplicate_session_count,
            },
            "full_session_aggregates": {
                "event_count": len(events),
                "session_duration_s": round(max(event.timestamp for event in events) - events[0].timestamp, 6),
                "failure_count": sum(event.result.value == "failure" for event in events),
            },
        })
    return {"events": event_rows, "traces": trace_rows}


def build_synchronized_bundle(
    sequences: SequencePairs,
    *,
    provenance: Optional[GenerationProvenance] = None,
) -> dict[str, Any]:
    provenance = provenance or build_generation_provenance(cfg)
    observations = to_detector_observation_df(sequences)
    manifest = field_manifest()
    manifest["legacy_representation"] = legacy_contract_for_sequences(sequences)
    provenance_view = to_provenance_view(sequences, provenance)
    validation = validate_synchronized_dataset(
        sequences,
        provenance=provenance,
        field_manifest=manifest,
        dataset_manifest=provenance_view["dataset"]["capabilities"],
    )
    return {
        "detector_observations": observations.to_dict(orient="records"),
        "ground_truth": to_ground_truth_views(sequences, validation),
        "provenance": provenance_view,
        "debug": to_debug_view(sequences),
        "field_manifest": manifest,
        "validation": validation.to_dict(),
    }


class SynchronizedOutputViews:
    """Save separated synchronized views; never write the legacy feature table."""

    def __init__(self, output_dir: str = "data/output"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def save(
        self,
        sequences: SequencePairs,
        *,
        stem: str = "iot_auth",
        provenance: Optional[GenerationProvenance] = None,
    ) -> dict[str, Path]:
        bundle = build_synchronized_bundle(sequences, provenance=provenance)
        paths = {
            "detector_observations": self.output_dir / f"{stem}_observations.csv",
            "ground_truth_events": self.output_dir / f"{stem}_ground_truth_events.csv",
            "ground_truth_traces": self.output_dir / f"{stem}_ground_truth_traces.csv",
            "provenance": self.output_dir / f"{stem}_provenance.json",
            "debug": self.output_dir / f"{stem}_debug.json",
            "field_manifest": self.output_dir / f"{stem}_field_manifest.json",
            "dataset_manifest": self.output_dir / f"{stem}_dataset_manifest.json",
            "validation_report": self.output_dir / f"{stem}_validation_report.json",
        }
        pd.DataFrame(bundle["detector_observations"]).to_csv(paths["detector_observations"], index=False)
        pd.DataFrame(bundle["ground_truth"]["events"]).to_csv(paths["ground_truth_events"], index=False)
        pd.DataFrame(bundle["ground_truth"]["traces"]).to_csv(paths["ground_truth_traces"], index=False)
        paths["provenance"].write_text(json.dumps(bundle["provenance"], indent=2, default=str), encoding="utf-8")
        paths["debug"].write_text(json.dumps(bundle["debug"], indent=2, default=str), encoding="utf-8")
        paths["field_manifest"].write_text(json.dumps(bundle["field_manifest"], indent=2), encoding="utf-8")
        paths["dataset_manifest"].write_text(
            json.dumps(bundle["provenance"]["dataset"]["capabilities"], indent=2),
            encoding="utf-8",
        )
        paths["validation_report"].write_text(
            json.dumps(bundle["validation"], indent=2), encoding="utf-8"
        )
        return paths


def legacy_contract_for_sequences(sequences: SequencePairs) -> dict[str, Any]:
    """Provide migration metadata without making legacy columns synchronized."""
    from simulator.data.output_views import to_feature_df

    return historical_feature_contract(to_feature_df(sequences).columns)
