from __future__ import annotations

from app.common.schemas import FeatureVector


FEATURE_COLUMNS = [
    "request_count_1m",
    "same_event_count_10m",
    "unique_dst_ports_5m",
    "login_failures_5m",
    "http_error_ratio_5m",
    "dns_query_length",
    "off_hours",
    "is_whitelisted",
    "asset_importance",
    "signature_severity",
    "baseline_score",
    "known_source",
    "known_event_type",
    "new_destination_ip",
    "new_destination_port",
]


def feature_vector_to_list(features: FeatureVector) -> list[float]:
    return [
        float(features.request_count_1m),
        float(features.same_event_count_10m),
        float(features.unique_dst_ports_5m),
        float(features.login_failures_5m),
        float(features.http_error_ratio_5m),
        float(features.dns_query_length),
        1.0 if features.off_hours else 0.0,
        1.0 if features.is_whitelisted else 0.0,
        float(features.asset_importance),
        float(features.signature_severity),
        float(features.baseline_score),
        1.0 if features.known_source else 0.0,
        1.0 if features.known_event_type else 0.0,
        1.0 if features.new_destination_ip else 0.0,
        1.0 if features.new_destination_port else 0.0,
    ]
