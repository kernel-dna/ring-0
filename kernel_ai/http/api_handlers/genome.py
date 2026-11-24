"""Kernel DNA's seccomp karyotype: each unit's calls against systemd's syscall groups."""

from flask import request

from kernel_ai.http.common import api_json


def syscall_genome():
    def _payload():
        from kernel_ai.services import syscall_genome as genome_service

        unit = request.args.get("unit", "").strip()
        return genome_service.get_unit(unit) if unit else genome_service.get_units()

    return api_json(_payload, exception_statuses=[(ValueError, 400)])
