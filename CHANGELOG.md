# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-09-27

### Added
- Helm chart packaging (`charts/ztre`) for automated deployment on Kubernetes.
- Configurable Helm values for agent runtime mode (`discovery`, `shadow`, `enforcement`), worker threads, resource limits, and Tetragon socket paths.
- Helm templates for `Namespace`, `ServiceAccount`, `ClusterRole`, `ClusterRoleBinding`, `ConfigMap`, `DaemonSet`, and `CiliumClusterwideNetworkPolicy`.
- Dynamic ConfigMap generation supporting process lineage whitelist, risk scoring policy, and agent configuration.
- Conditional deployment of Cilium quarantine network policy.
- Standard labels and helper templates conforming to Helm best practices.
- Post-install instruction notes (`NOTES.txt`).
- Automated container quarantine via pod labeling and Cilium network policy enforcement.
- Tetragon eBPF event streaming ingestion and real-time risk assessment engine.
