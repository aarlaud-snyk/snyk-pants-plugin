# coding=utf-8
# Copyright 2014 Pants project contributors (see CONTRIBUTORS.md).
# Licensed under the Apache License, Version 2.0 (see LICENSE).

from __future__ import absolute_import, division, print_function, unicode_literals

from twitter.common.collections import OrderedSet

from pants.backend.jvm.targets.jar_library import JarLibrary
from pants.backend.jvm.targets.jvm_app import JvmApp
from pants.backend.jvm.targets.jvm_target import JvmTarget
from pants.base.exceptions import TaskError
from pants.base.payload_field import JarsField, PythonRequirementsField
from pants.task.console_task import ConsoleTask

class DependenciesTask(ConsoleTask):
  """Print the target's dependencies."""

  @staticmethod
  def _is_jvm(target):
    return isinstance(target, (JarLibrary, JvmTarget, JvmApp))

  @classmethod
  def register_options(cls, register):
    super(DependenciesTask, cls).register_options(register)
    register('--internal-only', type=bool,
             help='Specifies that only internal dependencies should be included in the graph '
                  'output (no external jars).')
    register('--external-only', type=bool,
             help='Specifies that only external dependencies should be included in the graph '
                  'output (only external jars).')
    register('--transitive', default=True, type=bool,
             help='List transitive dependencies. Disable to only list dependencies defined '
                  'in target BUILD file(s).')

  def __init__(self, *args, **kwargs):
    super(DependenciesTask, self).__init__(*args, **kwargs)

    self.is_internal_only = self.get_options().internal_only
    self.is_external_only = 'true'
    self._transitive = self.get_options().transitive
    if self.is_internal_only and self.is_external_only:
      raise TaskError('At most one of --internal-only or --external-only can be selected.')

  @classmethod
  def product_types(cls):
    return ['dependencies']

  def console_output(self, unused_method_argument):
    ordered_closure = OrderedSet()
    for target in self.context.target_roots:
      if self._transitive:
        target.walk(ordered_closure.add)
      else:
        ordered_closure.update(target.dependencies)
    
    javaExternalDeps = list()
    pythonExternalDeps = list()
    for tgt in ordered_closure:
      if not self.is_external_only:
        yield tgt.address.spec
      if not self.is_internal_only:
        # TODO(John Sirois): We need an external payload abstraction at which point knowledge
        # of jar and requirement payloads can go and this hairball will be untangled.
        if isinstance(tgt.payload.get_field('requirements'), PythonRequirementsField):
          for requirement in tgt.payload.requirements:
            pythonExternalDeps.append('{}'.format(requirement.requirement))
            #yield str(requirement.requirement)
        elif isinstance(tgt.payload.get_field('jars'), JarsField):
          for jar in tgt.payload.jars:
            data = dict(org=jar.org, name=jar.name, rev=jar.rev)
            javaExternalDeps.append(data)
            
            #yield ('{org}:{name}:{rev}' if jar.rev else '{org}:{name}').format(**data)
    self.context.products.register_data('javaDependencies',javaExternalDeps)
    self.context.products.register_data('pythonDependencies',pythonExternalDeps)