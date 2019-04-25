from pants.goal.goal import Goal
from pants.goal.task_registrar import TaskRegistrar as task
from snyk.tasks.snyk import SnykTask
from snyk.tasks.dependencies import DependenciesTask

def register_goals():
    Goal.register(name="snyktest", description="Snyk Test your dependencies for vulnerabilities")
    task(name='dependencies', action=DependenciesTask).install('snyktest')
    task(name='snyk', action=SnykTask).install('snyktest')
