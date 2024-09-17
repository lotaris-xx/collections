# Handle locating and reading the contents of the node scripts which will then hand
# off to the module.

from __future__ import annotations

import os
import re
import shlex

from ansible.errors import (
    AnsibleError,
    AnsibleAction,
    _AnsibleActionDone,
    AnsibleActionFail,
    AnsibleActionSkip,
)
from ansible.module_utils.common.text.converters import to_bytes, to_native, to_text
from ansible.plugins.action import ActionBase


class ActionModule(ActionBase):

    def run(self, tmp=None, task_vars=None):
        """collect contents of node scripts"""
        if task_vars is None:
            task_vars = dict()

        validation_result, new_module_args = self.validate_argument_spec(
            argument_spec={
                "script_dir": {"type": "str", "required": True},
                "user_scripts": {"type": "dict", "required": True},
            },
        )

        result = super(ActionModule, self).run(tmp, task_vars)
        del tmp  # tmp no longer has any effect
        try:

            try:
                source = self._loader.get_real_file(
                    self._find_needle("files", source),
                    decrypt=self._task.args.get("decrypt", True),
                )
            except AnsibleError as e:
                raise AnsibleActionFail(to_native(e))

            result.update(
                self._low_level_execute_command(
                    cmd=script_cmd, in_data=exec_data, sudoable=True, chdir=chdir
                )
            )

        except AnsibleAction as e:
            result.update(e.result)

        return result
