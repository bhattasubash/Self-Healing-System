"""
Kubernetes Collector & Watcher Service for Temporal Store (PRD Section 8, F-04).

Discovers cluster resources and populates the SQLite bi-temporal engine:
- Deployments (spec, revisions, replicas, images, rollout state)
- ReplicaSets (revisions, pod templates, owner deployment UID)
- Pods (phase, conditions, restartCount, CrashLoopBackOff)
- Events (Warning, BackOff, Failed, Unhealthy)
- HorizontalPodAutoscalers (target deployment, desired/current replicas)
"""

from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import threading

import structlog

from app.services.temporal_store import (
    ChangeRecord,
    EntityRecord,
    ObservationRecord,
    TemporalStore,
)

logger = structlog.get_logger()


class KubernetesCollector:
    """Collects Kubernetes cluster state and records entities, changes, and observations."""

    def __init__(
        self,
        apps_api: Any = None,
        core_api: Any = None,
        autoscaling_api: Any = None,
    ) -> None:
        self.apps_api = apps_api
        self.core_api = core_api
        self.autoscaling_api = autoscaling_api
        self._log = logger.bind(component="k8s_collector")

    def _ensure_apis(self) -> None:
        """Lazily load Kubernetes configuration and APIs if not injected."""
        if self.apps_api is not None and self.core_api is not None:
            return

        try:
            from kubernetes import client, config

            try:
                config.load_incluster_config()  # type: ignore[no-untyped-call]
            except config.ConfigException:
                config.load_kube_config()  # type: ignore[no-untyped-call]

            if self.apps_api is None:
                self.apps_api = client.AppsV1Api()
            if self.core_api is None:
                self.core_api = client.CoreV1Api()
            if self.autoscaling_api is None:
                try:
                    self.autoscaling_api = client.AutoscalingV2Api()
                except Exception:
                    self.autoscaling_api = client.AutoscalingV1Api()
        except Exception as exc:
            self._log.warning("k8s_api_client_init_failed", error=str(exc))

    def _record_deployment_sync(
        self,
        temporal_store: TemporalStore,
        deploy: Any,
        default_ns: str = "default",
        change_source: str = "k8s_collector",
    ) -> EntityRecord | None:
        """Extracts and synchronously registers deployment entity and change into TemporalStore."""
        meta = getattr(deploy, "metadata", None)
        if not meta:
            return None
        uid = getattr(meta, "uid", None)
        name = getattr(meta, "name", None)
        if not uid or not name:
            return None
        ns = getattr(meta, "namespace", default_ns) or default_ns
        spec = getattr(deploy, "spec", None)
        status = getattr(deploy, "status", None)

        now = datetime.now(UTC)
        entity = EntityRecord(uid=str(uid), kind="Deployment", namespace=str(ns), name=str(name))
        temporal_store._record_entity_sync(entity)

        annotations = getattr(meta, "annotations", {}) or {}
        revision = annotations.get("deployment.kubernetes.io/revision", "1")
        template_spec = (
            getattr(spec.template, "spec", None)
            if spec and getattr(spec, "template", None)
            else None
        )
        containers = getattr(template_spec, "containers", []) if template_spec else []
        images = [getattr(c, "image", "") for c in containers]

        def _to_int(val: Any, default: int = 0) -> int:
            if isinstance(val, int):
                return val
            if isinstance(val, str) and val.isdigit():
                return int(val)
            return default

        replicas = _to_int(getattr(spec, "replicas", 1) if spec else 1, default=1)
        ready_replicas = _to_int(getattr(status, "ready_replicas", 0) if status else 0, default=0)
        updated_replicas = _to_int(getattr(status, "updated_replicas", 0) if status else 0, default=0)

        after_state = {
            "revision": revision,
            "replicas": replicas,
            "ready_replicas": ready_replicas,
            "updated_replicas": updated_replicas,
            "images": images,
            "rollout_in_flight": updated_replicas < replicas or ready_replicas < replicas,
        }

        summary = (
            f"Deployment {name} {change_source} (rev {revision}, "
            f"replicas {ready_replicas}/{replicas})"
        )
        change = ChangeRecord(
            entity_uid=str(uid),
            change_type="DEPLOYMENT_SYNC" if change_source == "k8s_collector" else "DEPLOYMENT_WATCH",
            summary=summary,
            before_state={},
            after_state=after_state,
            valid_from=now,
            source=change_source,
            actor="system",
        )
        temporal_store._record_change_sync(change)
        return entity

    async def sync_deployments(
        self, temporal_store: TemporalStore, namespace: str | None = None
    ) -> list[EntityRecord]:
        """Collects Deployments and records entities and state mutations."""
        self._ensure_apis()
        if not self.apps_api:
            return []

        loop = asyncio.get_running_loop()

        def _fetch() -> Any:
            if namespace:
                return self.apps_api.list_namespaced_deployment(namespace=namespace)
            return self.apps_api.list_deployment_for_all_namespaces()

        try:
            res = await loop.run_in_executor(None, _fetch)
        except Exception as exc:
            self._log.error("sync_deployments_failed", error=str(exc))
            return []

        records: list[EntityRecord] = []
        for deploy in getattr(res, "items", []):
            rec = self._record_deployment_sync(
                temporal_store, deploy, default_ns=namespace or "default"
            )
            if rec:
                records.append(rec)

        return records

    async def sync_replica_sets(
        self, temporal_store: TemporalStore, namespace: str | None = None
    ) -> list[EntityRecord]:
        """Collects ReplicaSets and registers revision history for deployments."""
        self._ensure_apis()
        if not self.apps_api:
            return []

        now = datetime.now(UTC)
        loop = asyncio.get_running_loop()

        def _fetch() -> Any:
            if namespace:
                return self.apps_api.list_namespaced_replica_set(namespace=namespace)
            return self.apps_api.list_replica_set_for_all_namespaces()

        try:
            res = await loop.run_in_executor(None, _fetch)
        except Exception as exc:
            self._log.error("sync_replica_sets_failed", error=str(exc))
            return []

        records: list[EntityRecord] = []
        for rs in getattr(res, "items", []):
            meta = rs.metadata
            spec = rs.spec
            uid = meta.uid
            ns = meta.namespace or "default"
            name = meta.name

            entity = EntityRecord(uid=uid, kind="ReplicaSet", namespace=ns, name=name)
            await temporal_store.record_entity(entity)
            records.append(entity)

            annotations = meta.annotations or {}
            revision = annotations.get("deployment.kubernetes.io/revision", "1")
            owner_refs = meta.owner_references or []
            owner_uid = owner_refs[0].uid if owner_refs else None

            containers = getattr(spec.template.spec, "containers", []) if spec.template else []
            images = [getattr(c, "image", "") for c in containers]

            change = ChangeRecord(
                entity_uid=uid,
                change_type="REVISION_REGISTERED",
                summary=f"ReplicaSet {name} revision {revision} (owner {owner_uid or 'none'})",
                before_state={},
                after_state={
                    "revision": revision,
                    "replicaset_uid": uid,
                    "replicaset_name": name,
                    "owner_deployment_uid": owner_uid,
                    "images": images,
                    "replicas": getattr(spec, "replicas", 0),
                },
                valid_from=now,
                source="k8s_collector",
                actor="system",
            )
            await temporal_store.record_change(change)

        return records

    async def sync_pods(
        self, temporal_store: TemporalStore, namespace: str | None = None
    ) -> list[EntityRecord]:
        """Collects Pods and records real-time health observations."""
        self._ensure_apis()
        if not self.core_api:
            return []

        now = datetime.now(UTC)
        loop = asyncio.get_running_loop()

        def _fetch() -> Any:
            if namespace:
                return self.core_api.list_namespaced_pod(namespace=namespace)
            return self.core_api.list_pod_for_all_namespaces()

        try:
            res = await loop.run_in_executor(None, _fetch)
        except Exception as exc:
            self._log.error("sync_pods_failed", error=str(exc))
            return []

        records: list[EntityRecord] = []
        for pod in getattr(res, "items", []):
            meta = pod.metadata
            status = pod.status
            uid = meta.uid
            ns = meta.namespace or "default"
            name = meta.name

            entity = EntityRecord(uid=uid, kind="Pod", namespace=ns, name=name)
            await temporal_store.record_entity(entity)
            records.append(entity)

            # Analyze pod health status
            phase = getattr(status, "phase", "Unknown")
            is_unhealthy = False
            unhealthy_reason = ""

            for cs in getattr(status, "container_statuses", []) or []:
                waiting = getattr(cs.state, "waiting", None) if getattr(cs, "state", None) else None
                if waiting:
                    reason = getattr(waiting, "reason", "")
                    if reason in ("CrashLoopBackOff", "ImagePullBackOff", "ErrImagePull", "Error"):
                        is_unhealthy = True
                        unhealthy_reason = reason
                        break
                if getattr(cs, "restart_count", 0) > 0 and not getattr(cs, "ready", False):
                    is_unhealthy = True
                    unhealthy_reason = f"Restarts({cs.restart_count})"
                    break

            if phase == "Failed":
                is_unhealthy = True
                unhealthy_reason = "PhaseFailed"

            if is_unhealthy:
                obs_status = "unhealthy"
            elif phase == "Running":
                obs_status = "healthy"
            else:
                obs_status = "pending"
            obs_value = 0.0 if is_unhealthy else (1.0 if phase == "Running" else 0.5)

            obs = ObservationRecord(
                entity_uid=uid,
                timestamp=now,
                metric_name="pod_status",
                value=obs_value,
                status=obs_status,
            )
            await temporal_store.record_observation(obs)

            # Correlate to deployment by app label or owner reference
            labels = meta.labels or {}
            app_name = labels.get("app") or labels.get("deployment")
            if app_name:
                deploy_entity = await temporal_store.get_entity_by_name(
                    namespace=ns, name=app_name, kind="Deployment"
                )
                if deploy_entity:
                    await temporal_store.record_observation(
                        ObservationRecord(
                            entity_uid=deploy_entity.uid,
                            timestamp=now,
                            metric_name=f"pod_{name}_{unhealthy_reason or 'status'}",
                            value=obs_value,
                            status=obs_status,
                        )
                    )

        return records

    async def sync_events(
        self, temporal_store: TemporalStore, namespace: str | None = None
    ) -> list[ObservationRecord]:
        """Collects Warning events and records telemetry observations."""
        self._ensure_apis()
        if not self.core_api:
            return []

        now = datetime.now(UTC)
        loop = asyncio.get_running_loop()

        def _fetch() -> Any:
            if namespace:
                return self.core_api.list_namespaced_event(namespace=namespace)
            return self.core_api.list_event_for_all_namespaces()

        try:
            res = await loop.run_in_executor(None, _fetch)
        except Exception as exc:
            self._log.error("sync_events_failed", error=str(exc))
            return []

        records: list[ObservationRecord] = []
        for event in getattr(res, "items", []):
            event_type = getattr(event, "type", "Normal")
            reason = getattr(event, "reason", "")
            involved = getattr(event, "involved_object", None)
            if not involved:
                continue

            target_uid = getattr(involved, "uid", None)
            target_name = getattr(involved, "name", "")
            target_ns = getattr(involved, "namespace", "") or namespace or "default"

            # If UID not present on event, resolve entity by name
            if not target_uid and target_name:
                ent = await temporal_store.get_entity_by_name(
                    namespace=target_ns, name=target_name
                )
                target_uid = ent.uid if ent else None

            if not target_uid:
                continue

            if not await temporal_store.get_entity(target_uid):
                raw_kind = getattr(involved, "kind", None)
                kind_str = raw_kind if isinstance(raw_kind, str) and raw_kind else "Pod"
                await temporal_store.record_entity(
                    EntityRecord(
                        uid=str(target_uid),
                        kind=kind_str,
                        namespace=str(target_ns),
                        name=str(target_name or target_uid),
                    )
                )

            is_warning = event_type == "Warning" or reason in ("BackOff", "Failed", "Unhealthy")
            obs = ObservationRecord(
                entity_uid=target_uid,
                timestamp=now,
                metric_name=f"k8s_event_{reason}",
                value=0.0 if is_warning else 1.0,
                status="unhealthy" if is_warning else "healthy",
            )
            await temporal_store.record_observation(obs)
            records.append(obs)

        return records

    async def sync_hpa(
        self, temporal_store: TemporalStore, namespace: str | None = None
    ) -> list[EntityRecord]:
        """Collects Horizontal Pod Autoscalers and records scaling metrics."""
        self._ensure_apis()
        if not self.autoscaling_api:
            return []

        now = datetime.now(UTC)
        loop = asyncio.get_running_loop()

        def _fetch() -> Any:
            if namespace:
                return self.autoscaling_api.list_namespaced_horizontal_pod_autoscaler(
                    namespace=namespace
                )
            return self.autoscaling_api.list_horizontal_pod_autoscaler_for_all_namespaces()

        try:
            res = await loop.run_in_executor(None, _fetch)
        except Exception as exc:
            self._log.error("sync_hpa_failed", error=str(exc))
            return []

        records: list[EntityRecord] = []
        for hpa in getattr(res, "items", []):
            meta = hpa.metadata
            spec = hpa.spec
            status = getattr(hpa, "status", None)
            uid = meta.uid
            ns = meta.namespace or "default"
            name = meta.name

            entity = EntityRecord(
                uid=uid, kind="HorizontalPodAutoscaler", namespace=ns, name=name
            )
            await temporal_store.record_entity(entity)
            records.append(entity)

            target_ref = getattr(spec, "scale_target_ref", None)
            target_name = getattr(target_ref, "name", "") if target_ref else ""
            current_replicas = getattr(status, "current_replicas", 0) if status else 0
            desired_replicas = getattr(status, "desired_replicas", 0) if status else 0

            hpa_summary = (
                f"HPA {name} for {target_name} "
                f"(replicas: {current_replicas} -> {desired_replicas})"
            )
            change = ChangeRecord(
                entity_uid=uid,
                change_type="HPA_SYNC",
                summary=hpa_summary,
                before_state={},
                after_state={
                    "target_name": target_name,
                    "current_replicas": current_replicas,
                    "desired_replicas": desired_replicas,
                },
                valid_from=now,
                source="k8s_collector",
                actor="system",
            )
            await temporal_store.record_change(change)

        return records

    async def sync_all(
        self, temporal_store: TemporalStore, namespace: str | None = None
    ) -> dict[str, int]:
        """Synchronizes all Kubernetes resources into the temporal store."""
        deploys = await self.sync_deployments(temporal_store, namespace)
        rs = await self.sync_replica_sets(temporal_store, namespace)
        pods = await self.sync_pods(temporal_store, namespace)
        events = await self.sync_events(temporal_store, namespace)
        hpas = await self.sync_hpa(temporal_store, namespace)

        return {
            "deployments": len(deploys),
            "replica_sets": len(rs),
            "pods": len(pods),
            "events": len(events),
            "hpas": len(hpas),
        }

    def is_telemetry_fresh(
        self, temporal_store: TemporalStore, threshold_seconds: int = 120
    ) -> bool:
        """Checks if recent observation telemetry exists within the freshness threshold window."""
        latest = temporal_store.get_latest_observation_time()
        if not latest:
            return False
        # Normalize timezone awareness
        now = datetime.now(UTC)
        if latest.tzinfo is None:
            latest = latest.replace(tzinfo=UTC)
        age = (now - latest).total_seconds()
        return age <= threshold_seconds

    async def sync_namespaces(
        self, temporal_store: TemporalStore, namespaces: list[str]
    ) -> dict[str, int]:
        """Synchronizes Kubernetes resources only for specified allowlisted namespaces."""
        totals = {"deployments": 0, "replica_sets": 0, "pods": 0, "events": 0, "hpas": 0}
        for ns in namespaces:
            res = await self.sync_all(temporal_store, namespace=ns)
            for k, v in res.items():
                totals[k] += v
        return totals

    async def run_watches_in_background(
        self,
        temporal_store: TemporalStore,
        namespaces: list[str],
        stop_event: threading.Event,
        poll_fallback_seconds: float = 15.0,
    ) -> None:
        """
        Runs blocking Kubernetes watches off the asyncio event loop using worker threads.
        Handles 410 Gone / resourceVersion expiration, automatic reconnects,
        and watches only allowlisted namespaces.
        """
        def _watch_loop() -> None:
            self._ensure_apis()
            if not self.apps_api or not self.core_api:
                return

            from kubernetes import watch

            w = watch.Watch()  # type: ignore[no-untyped-call]
            for ns in namespaces:
                if stop_event.is_set():
                    break
                resource_version: str | None = None
                while not stop_event.is_set():
                    try:
                        kwargs: dict[str, Any] = {
                            "timeout_seconds": int(max(poll_fallback_seconds, 1))
                        }
                        if resource_version:
                            kwargs["resource_version"] = resource_version
                        for event in w.stream(  # type: ignore[no-untyped-call]
                            self.apps_api.list_namespaced_deployment,
                            namespace=ns,
                            **kwargs,
                        ):
                            if stop_event.is_set():
                                break
                            raw_obj = (
                                event.get("object")
                                if isinstance(event, dict)
                                else getattr(event, "object", None)
                            )
                            if raw_obj:
                                meta = getattr(raw_obj, "metadata", None)
                                if meta and hasattr(meta, "resource_version"):
                                    resource_version = meta.resource_version
                                if meta and getattr(meta, "uid", None):
                                    try:
                                        self._record_deployment_sync(
                                            temporal_store,
                                            raw_obj,
                                            default_ns=ns,
                                            change_source="k8s_collector_watch",
                                        )
                                    except Exception as rec_err:
                                        self._log.warning(
                                            "watch_record_deployment_error", error=str(rec_err)
                                        )
                        if stop_event.is_set():
                            break
                    except Exception as exc:
                        # Handle 410 Gone / expired resourceVersion
                        status_code = getattr(exc, "status", None)
                        is_expired = (
                            status_code == 410 or "410" in str(exc) or "expired" in str(exc).lower()
                        )
                        if is_expired:
                            self._log.info(
                                "watch_resource_version_expired_resetting", error=str(exc)
                            )
                            resource_version = None
                        else:
                            self._log.warning(
                                "watch_stream_interrupted_reconnecting", error=str(exc)
                            )
                        if stop_event.is_set():
                            break
                        time.sleep(0.1)

        await asyncio.to_thread(_watch_loop)
