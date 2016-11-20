# Last Modified: 2016.11.19 /coding: utf-8
# Copyright: © 2011, 2015-2016 Landon Bouma.
# License: GPLv3. See LICENSE.txt.
#  vim:tw=0:ts=4:sw=4:noet

import os
import sys

# argparse succeeds optparse and requires Python >= 2.7.
# If you need argparse for Py < 2.7, copy the one from
#  /usr/lib/python2.7/argparse.py.
import argparse
import signal
import threading
import time

from xdg import BaseDirectory

import chjson
#import schematics

import pyoiler_timedelta

from pyoiler_logging import *

__all__ = [
	'ArgumentParser_Wrap',
	'Simple_Script_Base',
]

# Usage: Derive a class from this class and override
#        the two functions, prepare() and verify().

class ArgumentParser_Wrap(argparse.ArgumentParser):

	print_on_error = False

	__slots__ = (
		'script_name',
		'script_version',
		'cli_opts',
		'handled',
		)

	def __init__(self,
		description,
		script_name=None,
		script_version=None,
		usage=None
	):
		argparse.ArgumentParser.__init__(self, description, usage, add_help=False)
		if script_name is not None:
			self.script_name = script_name
		else:
			self.script_name = os.path.basename(sys.argv[0])
		if script_version is not None:
			self.script_version = script_version
		else:
			self.script_version = 'X'
		self.cli_opts = None
		self.handled = False

	def get_opts(self):
		self.prepare();
		self.parse();
		self.verify_();
		assert(self.cli_opts is not None)
		return self.cli_opts

	def prepare(self):
		'''
		Defines default CLI options for this script.

		Currently there's just one shared option: -v/-version.

		Derived classes should override this function
		to define more arguments.
		'''
		default_prefix = '-'
		# Cxpx: /usr/lib/python2.7/argparse.py::l.1599
		#  I want -? to work, dammit!
		self.add_argument(default_prefix+'?',
			default_prefix+'h', default_prefix*2+'help',
			action='help',# default=SUPPRESS,
			help='show this help message and exit'
		)

		# Script version.
		self.add_argument(
			'-v', '--version',
			action='version',
			version=('%s version %2s' % (
			self.script_name, self.script_version,))
		)

	def parse(self):
		'''Parse the command line arguments.'''
		self.cli_opts = self.parse_args()

	# *** Helpers: Verify the arguments.

	def verify_(self):
		verified = self.verify()
		# Mark handled if we handled an error, else just return.
		if not verified:
			msg = 'Type "%s --help" for usage.' % (sys.argv[0],)
			if self.print_on_error:
				print(msg)
			else:
				info(msg)
			self.handled = True
		return verified

	def verify(self):
		# Placeholder; derived classes may override.
		ok = True
		return ok

# ***

class Simple_Script_Base(object):

	__slots__ = (
		'argparser',
		'cli_args',
		'cli_opts',
		'exit_value',
		)

	def __init__(self, argparser):
		self.argparser = argparser
		self.cli_args = None
		self.cli_opts = None
		# If we run as a script, by default we'll return a happy exit code.
		self.exit_value = 0

	def cleanup(self):
		debug('cleanup')
		pass

	def go(self):
		'''
		Parse the command line arguments. If the command line parser didn't
		handle a --help or --version command, call the command processor.
		'''

		time_0 = time.time()

		# Read the CLI args
		self.cli_args = self.argparser()
		self.cli_opts = self.cli_args.get_opts()

		if not self.cli_args.handled:

			info('Welcome to the %s!' % (
				self.cli_args.script_name,
			))

			self.ctrl_c_event = threading.Event()
			signal.signal(signal.SIGINT, self.ctrl_c_handler)

			# NOTE: It's up to the caller to call this, if they care:
			#  self.app_cfg_load()

			# Call the derived class's go function.
			self.go_main()

		info('Script completed in %s' % (
			pyoiler_timedelta.time_format_elapsed(time_0),
		))

		# If we run as a script, be sure to return an exit code.
		return self.exit_value

	def ctrl_c_handler(self, signum, frame):
		# If you Pipe() something with a reference to this object, you'll
		# see this fcn. called twice, once for each reference, since the
		# app was duplicated when you Pipe()ed. Interestingly, from either
		# viewpoint, both references to this object have the same id, even
		# though they don't actually point to the same physical memory.
		# E.g., if you change a param on one, it's not reflected on t'other.
		# Diagnosis: Process is cloned -- along with IDs -- but object are
		# truly (expectedly) in separate memory spaces. At least in this
		# instance -- the Ctrl-c handler -- we don't need to care about
		# using a multiprocessing-aware event.
		debug('ctrl_c_handler: id: %s / master_thread: %s / signum: %s / frame: %s' % (
			id(self), self.master_thread, signum, frame,
		))
		self.ctrl_c_event.set()
		self.cleanup()

# FIXME: COPIED
   # This is a useful utility fcn. from CcpV1's schema-upgrade.py.
   # Prints a message and gobbles input until newline;
   # Returns True if the input is 'y'.
	def ask_yes_no(self, msg):
		resp = raw_input(msg + ' (y|[N]) ')
		yes = resp.lower() in ('y', 'yes',)
		return yes

# FIXME: COPIED
	def ask_question(self, msg, default, the_type=str):
		resp = raw_input('%s [%s]: ' % (msg, default,))
		if resp == '':
			resp = default
		else:
			try:
				resp = the_type(resp)
			except ValueError:
				error('ask_question: invalid input: %s' % (msg,))
				raise
		return resp

	def go_main(self):
		pass # Abstract.

	def app_cfg_load(self, cfg_filename, cfg_default):
		# See:
		#  http://pyxdg.readthedocs.io/en/latest/_modules/xdg/BaseDirectory.html

		# This (`mkdir -p`s and) returns a path to the application config,
		# e.g., '/home/${USER}/.config/check\xe2\x9c\x93++'
		cfg_base = BaseDirectory.save_config_path(application_resource)
		self.cfg_path = os.path.join(cfg_base, cfg_filename)
		self.cfg_data = None
		if os.path.isfile(self.cfg_path):
			with open(self.cfg_path, 'r') as f_in:
				try:
					raw_data = f_in.read()
					if raw_data:
						self.cfg_data = chjson.decode(raw_data)
					# else, leave self.cfg_data = None and we'll create it.
				except chjson.DecodeError as err:
					#raise User_Exception()
					print(
						"Whoopsie! What's wrong with the app config? It doesn't look like JSON: %s"
						% (cfg_path,)
					)
					print('Overwriting app config and starting fresh, sorry!')
		if self.cfg_data is None:
			self.cfg_data = copy.deepcopy(cfg_default)

	def app_cfg_dump(self):
		try:
			with open(self.cfg_path, 'w') as f_out:
				#f_out.write(json.dumps(self.cfg_data))
				f_out.write(chjson.encode(self.cfg_data))
		except Exception as err:
			warning('Failed: Could not write app config to: %s [%s]' % (
				self.cfg_path, str(err),
			))

# ***

if (__name__ == '__main__'):
	 pass

