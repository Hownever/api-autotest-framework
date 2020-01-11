# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
# See LICENSE for more details.
#
# Copyright: JD Inc. 2019
# Authors: likui <likui34@jd.com>

"""
Plugin to run httprunner tests in Avocado
"""

import logging
import os
import fnmatch
import glob

from avocado.core import loader
from avocado.core import output
from avocado.core import test
from avocado.core.plugin_interfaces import CLI
from httprunner.api import HttpRunner
from httprunner import validator


class HttpRunnerTest(test.SimpleTest):

    """
    Run a Httprunner yaml test as a SIMPLE test.
    """

    def __init__(self,
                 name,
                 params=None,
                 base_logdir=None,
                 job=None,
                 executable=None,
                 options=None,):
        self.hrun_options = options
        super(HttpRunnerTest, self).__init__(name, params, base_logdir, job,
                                             executable)

    @property
    def filename(self):
        """
        Returns the path of the yaml test suite.
        """
        return self._filename.split(':')[0]

    def test(self):
        """
        Create the Httprunner runner obj and execute it.
        """

        runner = HttpRunner(
            failfast=getattr(self.hrun_options, "fail_fast", None),
            save_tests=getattr(self.hrun_options, "save_tests", None),
            report_template=getattr(self.hrun_options, "report_template", None),
            report_dir=getattr(self.hrun_options, "report_dir", self.logdir),
            run_case=self.name.name
        )
        try:
            yamlfile = self.name.name
            runner.run(yamlfile, dot_env_path=getattr(self.hrun_options, "dot_env_path", None))
            result = runner.summary
        except Exception:
            self.log.error("!!!!!!!!!! exception stage: {} !!!!!!!!!!".format(runner.exception_stage))
            raise
        if not result.get('success', False):
            self.fail('hrun(HttpRunner) execution test failed: '
                      '%s' % result.get('stat', {}).get("testcases", {}))


class NotHttpRunnerTest(object):

    """
    Not a httprunner test (for reporting purposes)
    """


class HttpRunnerLoader(loader.TestLoader):
    """
    HttpRunner loader class
    """
    name = "httprunner"

    def __init__(self, args, extra_params):
        super(HttpRunnerLoader, self).__init__(args, extra_params)

    def discover(self, url, which_tests=loader.DiscoverMode.DEFAULT):
        avocado_suite = []

        if url is None:
            return []

        try:
            if validator.is_testcase_path(url):
                pass
            elif validator.is_testcases(url):
                pass
            else:
                return [(NotHttpRunnerTest, {"name": "%s: No httprunner-like tests found"
                                             % url})]
        except Exception as data:
            if which_tests == loader.DiscoverMode.ALL:
                return [(NotHttpRunnerTest, {"name": "%s: %s" % (url, data)})]
            return []

        if os.path.isfile(url):
            avocado_suite.append((HttpRunnerTest, {'name': url,
                                                   'options': self.args}))
        if os.path.isdir(url):
            for item in self._find_files(url):
                avocado_suite.append((HttpRunnerTest, {'name': item,
                                                       'options': self.args}))

        if which_tests == loader.DiscoverMode.ALL and not avocado_suite:
            return [(NotHttpRunnerTest, {"name": "%s: No httprunner-like tests found"
                                         % url})]
        return avocado_suite

    @staticmethod
    def _find_files(path, recursive=True):
        pattern = '*.yml'
        pattern2 = '*.yaml'
        if recursive:
            matches = []
            for root, _, filenames in os.walk(path):
                for filename in fnmatch.filter(filenames, pattern):
                    matches.append(os.path.join(root, filename))
                for filename in fnmatch.filter(filenames, pattern2):
                    matches.append(os.path.join(root, filename))
            return matches

        if path != '.':
            pattern = os.path.join(path, pattern)
        return glob.iglob(pattern)

    @staticmethod
    def get_type_label_mapping():
        return {HttpRunnerTest: 'HTTPRUNNER',
                NotHttpRunnerTest: "!HTTPRUNNER"}

    @staticmethod
    def get_decorator_mapping():
        return {HttpRunnerTest: output.TERM_SUPPORT.healthy_str,
                NotHttpRunnerTest: output.TERM_SUPPORT.fail_header_str}


class HttpRunnerCLI(CLI):

    """
    Run HttpRunner tests
    """

    name = 'hrun'
    description = "HttpRunner options for 'run' subcommand"

    def configure(self, parser):
        run_subcommand_parser = parser.subcommands.choices.get('run', None)
        if run_subcommand_parser is None:
            return

        msg = 'HttpRunner test '
        cmd_parser = run_subcommand_parser.add_argument_group(msg)
        cmd_parser.add_argument(
            '--log-level', default='INFO',
            help="Specify logging level, default is INFO.")
        cmd_parser.add_argument(
            '--log-file',
            help="Write logs to specified file path.")
        cmd_parser.add_argument(
            '--dot-env-path',
            help="Specify .env file path, which is useful for keeping sensitive data.")
        cmd_parser.add_argument(
            '--report-template',
            help="specify report template path.")
        cmd_parser.add_argument(
            '--report-dir',
            help="specify report save directory.")
        cmd_parser.add_argument(
            '--fail-fast', action='store_true', default=False,
            help="Stop the test run on the first error or failure.")
        cmd_parser.add_argument(
            '--save-tests', action='store_true', default=False,
            help="Save loaded tests and parsed tests to JSON file.")
        cmd_parser.add_argument(
            '--startproject',
            help="Specify new project name.")
        cmd_parser.add_argument(
            '--validate', nargs='*',
            help="Validate JSON testcase format.")
        cmd_parser.add_argument(
            '--prettify', nargs='*',
            help="Prettify JSON testcase format.")

    def run(self, args):
        loader.loader.register_plugin(HttpRunnerLoader)
