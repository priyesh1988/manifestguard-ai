from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


BUILTIN_KYVERNO_POLICIES: list[dict[str, Any]] = [
    {
        'apiVersion': 'kyverno.io/v1',
        'kind': 'ClusterPolicy',
        'metadata': {'name': 'manifestguard-require-non-root'},
        'spec': {
            'validationFailureAction': 'Audit',
            'background': True,
            'rules': [
                {
                    'name': 'require-run-as-non-root',
                    'match': {'any': [{'resources': {'kinds': ['Pod']}}]},
                    'validate': {
                        'message': 'Containers must set securityContext.runAsNonRoot=true.',
                        'pattern': {
                            'spec': {
                                'containers': [
                                    {'securityContext': {'runAsNonRoot': True}}
                                ]
                            }
                        },
                    },
                }
            ],
        },
    },
    {
        'apiVersion': 'kyverno.io/v1',
        'kind': 'ClusterPolicy',
        'metadata': {'name': 'manifestguard-disable-privilege-escalation'},
        'spec': {
            'validationFailureAction': 'Audit',
            'background': True,
            'rules': [
                {
                    'name': 'require-no-priv-esc',
                    'match': {'any': [{'resources': {'kinds': ['Pod']}}]},
                    'validate': {
                        'message': 'Containers must set allowPrivilegeEscalation=false.',
                        'pattern': {
                            'spec': {
                                'containers': [
                                    {'securityContext': {'allowPrivilegeEscalation': False}}
                                ]
                            }
                        },
                    },
                }
            ],
        },
    },
]


def export_builtin_kyverno(output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        yaml.safe_dump_all(BUILTIN_KYVERNO_POLICIES, sort_keys=False),
        encoding='utf-8',
    )
