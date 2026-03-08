"""
Tests unitaires pour baseline/engine.py
"""

import pytest
import json
from pathlib import Path
from datetime import datetime

from ghost_hunter.core.baseline.engine import BaselineEngine
from ghost_hunter.core.contracts import (
    InterceptedRequest,
    BaselineRecord,
    DiffResult,
)


# ==================== Fixtures ====================

@pytest.fixture
def baseline_engine(tmp_path):
    return BaselineEngine(storage_dir=tmp_path / "baselines")


@pytest.fixture
def sample_request():
    return InterceptedRequest(
        method="GET",
        url="https://api.example.com/users/123",
        host="api.example.com",
        path="/users/123",
        query_params={"id": "123"},
        response_status=200,
        response_body="{'user': 'test'}",
        response_headers={"content-type": "application/json"},
        response_time_ms=150.0,
    )


@pytest.fixture
def sample_baseline():
    return BaselineRecord(
        endpoint_hash="abc123",
        method="GET",
        url_template="/users/{id}",
        status_code=200,
        body_hash="d41d8cd98f00b204e9800998ecf8427e",
        body_length=100,
        response_time_ms=150,
        headers_hash="hash123",
        content_type="application/json",
    )


# ==================== Tests ====================

class TestBaselineEngine:
    
    def test_engine_creation(self, tmp_path):
        engine = BaselineEngine(storage_dir=tmp_path / "test")
        assert engine.storage_dir.exists()
        assert engine.count() == 0
    
    def test_compute_endpoint_hash(self, baseline_engine, sample_request):
        hash1 = baseline_engine.compute_endpoint_hash(sample_request)
        hash2 = baseline_engine.compute_endpoint_hash(sample_request)
        
        assert hash1 == hash2
        assert len(hash1) == 16
    
    def test_different_methods_different_hash(self, baseline_engine, sample_request):
        hash_get = baseline_engine.compute_endpoint_hash(sample_request)
        
        sample_request.method = "POST"
        hash_post = baseline_engine.compute_endpoint_hash(sample_request)
        
        assert hash_get != hash_post


class TestBaselineRecording:
    
    def test_record_baseline(self, baseline_engine, sample_request):
        record = baseline_engine.record(sample_request)
        
        assert record.method == "GET"
        assert record.status_code == 200
        assert record.body_length > 0
        assert baseline_engine.count() == 1
    
    def test_record_persists_to_disk(self, baseline_engine, sample_request):
        record = baseline_engine.record(sample_request)
        
        # Vérifier que le fichier existe
        file_path = baseline_engine.storage_dir / f"{record.endpoint_hash}.json"
        assert file_path.exists()
    
    def test_get_baseline(self, baseline_engine, sample_request):
        baseline_engine.record(sample_request)
        
        retrieved = baseline_engine.get(sample_request)
        
        assert retrieved is not None
        assert retrieved.status_code == 200
    
    def test_has_baseline(self, baseline_engine, sample_request):
        assert baseline_engine.has_baseline(sample_request) is False
        
        baseline_engine.record(sample_request)
        
        assert baseline_engine.has_baseline(sample_request) is True


class TestBaselineComparison:
    
    def test_compare_identical(self, baseline_engine, sample_baseline):
        attack_response = {
            "status_code": 200,
            "body": "x" * 100,  # Same length
            "response_time_ms": 150,
            "headers": {},
        }
        
        # Hack: set body_hash to match
        import hashlib
        sample_baseline.body_hash = hashlib.md5(attack_response["body"].encode()).hexdigest()
        
        result = baseline_engine.compare(sample_baseline, attack_response)
        
        assert result.is_suspicious is False
        assert result.anomaly_score < 30
    
    def test_compare_status_changed(self, baseline_engine, sample_baseline):
        attack_response = {
            "status_code": 500,
            "body": "",
            "response_time_ms": 150,
        }
        
        result = baseline_engine.compare(sample_baseline, attack_response)
        
        assert result.status_changed is True
        assert result.anomaly_score >= 30
        assert "Status changed" in result.anomalies[0]
    
    def test_compare_timing_anomaly(self, baseline_engine, sample_baseline):
        attack_response = {
            "status_code": 200,
            "body": "",
            "response_time_ms": 6000,  # 6 seconds
        }
        
        result = baseline_engine.compare(sample_baseline, attack_response)
        
        assert result.timing_anomaly is True
        assert result.timing_delta_ms > 5000
        assert result.anomaly_score >= 30
    
    def test_compare_body_length_change(self, baseline_engine, sample_baseline):
        attack_response = {
            "status_code": 200,
            "body": "x" * 200,  # Double the size
            "response_time_ms": 150,
        }
        
        result = baseline_engine.compare(sample_baseline, attack_response)
        
        assert result.body_changed is True
        assert result.body_length_delta == 100
    
    def test_compare_new_cookies(self, baseline_engine, sample_baseline):
        attack_response = {
            "status_code": 200,
            "body": "",
            "response_time_ms": 150,
            "headers": {"set-cookie": "admin=true; Path=/"},
        }
        
        result = baseline_engine.compare(sample_baseline, attack_response)
        
        assert result.headers_changed is True


class TestBaselinePersistence:
    
    def test_load_existing_baselines(self, tmp_path, sample_request):
        # Créer un engine et enregistrer
        engine1 = BaselineEngine(storage_dir=tmp_path / "baselines")
        engine1.record(sample_request)
        
        # Créer un nouveau engine avec le même stockage
        engine2 = BaselineEngine(storage_dir=tmp_path / "baselines")
        
        assert engine2.count() == 1
        assert engine2.has_baseline(sample_request)
    
    def test_clear_baselines(self, baseline_engine, sample_request):
        baseline_engine.record(sample_request)
        assert baseline_engine.count() == 1
        
        baseline_engine.clear()
        
        assert baseline_engine.count() == 0


class TestVariations:
    
    def test_record_variation(self, baseline_engine, sample_request):
        baseline_engine.record(sample_request)
        
        baseline_engine.record_variation(
            sample_request,
            "Known variation: different user data"
        )
        
        record = baseline_engine.get(sample_request)
        assert len(record.known_variations) == 1
        assert "Known variation" in record.known_variations[0]["description"]


class TestListEndpoints:
    
    def test_list_endpoints(self, baseline_engine, sample_request):
        baseline_engine.record(sample_request)
        
        endpoints = baseline_engine.list_endpoints()
        
        assert len(endpoints) == 1
        assert "/users/{id}" in endpoints[0]
