# Handle locating and reading the contents of the node scripts which will then hand
# off to the module.

from __future__ import annotations

from ansible.errors import (
    AnsibleError,
    AnsibleAction,
    AnsibleActionFail,
    AnsibleFileNotFound,
)
from ansible.module_utils.common.text.converters import to_native
from ansible.plugins.action import ActionBase


class ActionModule(ActionBase):

    def run(self, tmp=None, task_vars=None):
        """collect contents of node scripts"""
        if task_vars is None:
            task_vars = dict()

        validation_result, new_module_args = self.validate_argument_spec(
            argument_spec={
                "password": {"type": "str"},
                "script_dir": {"type": "str", "required": True},
                "site": {"type": "str", "required": True},
                "state": {"type": "str", "required": False, "default": "present"},
                "user_scripts": {"type": "list", "required": True},
                "token": {"type": "str"},
                "username": {"type": "str"},
            },
        )

        result = super(ActionModule, self).run(tmp, task_vars)
        del tmp  # tmp no longer has any effect

        if new_module_args["token"]:
            del new_module_args["username"]
            del new_module_args["password"]

        try:
            for user_script in new_module_args["user_scripts"]:
                try:
                    fp = self._loader.get_real_file(
                        self._find_needle("files", user_script["file"]),
                        decrypt=self._task.args.get("decrypt", True),
                    )

                    user_script["contents"] = to_native(open(fp, "rb").read())

                except AnsibleFileNotFound:

                    result["failed"] = True
                    result["msg"] = (
                        f"could not find user_script {user_script['file']} on controller, run with -vvvvv to see paths searched."
                    )
                    return result

                except AnsibleError as e:
                    raise AnsibleActionFail(to_native(e))

            result.update(
                self._execute_module(
                    "rhc.maas_settings.maas_node_scripts",
                    module_args=new_module_args,
                    task_vars=task_vars,
                    wrap_async=self._task.async_val,
                )
            )

        except AnsibleAction as e:
            result.update(e.result)

        return result
