# (c) 2012, Daniel Hokka Zakrisson <daniel@hozac.com>
# (c) 2017 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import annotations

from ansible.errors import AnsibleError, AnsibleOptionsError, AnsibleLookupError
from ansible.plugins.lookup import LookupBase
from ansible.module_utils.common.text.converters import to_text
from ansible.utils.display import Display

display = Display()


class LookupFile(LookupBase):

    def run(self, terms, variables=None, **kwargs):

        ret = []
        self.set_options(var_options=variables, direct=kwargs)

        for term in terms:
            display.debug("File lookup term: %s" % term)
            # Find the file in the expected search path
            try:
                lookupfile = self.find_file_in_search_path(
                    variables, "files", term, ignore_missing=True
                )
                display.vvvv("File lookup using %s as file" % lookupfile)
                if lookupfile:
                    b_contents, show_data = self._loader._get_file_contents(lookupfile)
                    contents = to_text(b_contents, errors="surrogate_or_strict")
                    if self.get_option("lstrip"):
                        contents = contents.lstrip()
                    if self.get_option("rstrip"):
                        contents = contents.rstrip()
                    ret.append(contents)
                else:
                    # TODO: only add search info if abs path?
                    raise AnsibleOptionsError(
                        "file not found, use -vvvvv to see paths searched"
                    )
            except AnsibleError as e:
                raise AnsibleLookupError(
                    "The 'file' lookup had an issue accessing the file '%s'" % term,
                    orig_exc=e,
                )

        return ret
