# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Models of workflows, composite Actions and reusable workflow calls (plan §3.2, T1-T6).

Built on the fail-closed reader in :mod:`ssc_guardian.yaml_subset`. Each model
exposes every ``uses:`` reference with its place: the file, the job and the
step, and the line. A ``uses:`` is read only where GitHub reads one: a step's
``uses`` (in a workflow job or a composite Action's ``runs.steps``) and a job's
``uses`` (a reusable workflow call). Text in a ``run:`` block, or a key named
``uses`` anywhere else (under ``with:``, say), is never a reference.

Each reference is kept exactly as written. A reference to another repository
(``OWNER/REPO[/PATH]@REF``) is checked with the ``action`` and ``git-ref``
grammars (contracts §6); one that fails raises
:class:`~ssc_guardian.grammars.MalformedValueError` (``malformed-name``, exit 1).
Merging two spellings of one Action (D18) is the handler's job, not the model's.

A file whose structure is not a workflow or an Action's metadata as read here
(``jobs`` not a mapping, a step that is not a mapping, a ``uses`` that is not one
value) is refused like a form outside the subset:
:class:`~ssc_guardian.yaml_subset.UnsupportedYamlError` (exit 2), naming the
file and line. Building a model is read-only and gives the same model on every run.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from ssc_guardian import yaml_subset
from ssc_guardian.findings import record_site
from ssc_guardian.grammars import Field, MalformedValueError, check
from ssc_guardian.yaml_subset import MappingNode, Node, ScalarNode, SequenceNode, UnsupportedYamlError

_STRUCTURE = "unexpected structure"
DOCKER_PREFIX = "docker://"


class UsesKind(StrEnum):
    ACTION = "action"  # a step's OWNER/REPO[/PATH]@REF
    REUSABLE_WORKFLOW = "reusable-workflow"  # a job's OWNER/REPO/PATH@REF
    LOCAL = "local"  # ./PATH in the same repository: an Action, or a reusable workflow for a job
    DOCKER = "docker"  # a step's docker://IMAGE


@dataclass(frozen=True)
class UsesReference:
    """One ``uses:`` value exactly as written, and where it was found.

    ``job`` is the job's ID (None in an Action's metadata); ``step`` is the
    0-based position in the job's or Action's ``steps`` (None for a job's own
    ``uses``). ``action`` and ``ref`` are the two halves of a reference to
    another repository, each grammar-checked; both are None for a local or
    Docker reference.
    """

    raw: str
    kind: UsesKind
    file: str
    line: int
    job: str | None
    step: int | None
    action: str | None = None
    ref: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, UsesKind):
            raise TypeError("a UsesKind names the reference's kind")
        remote = self.kind in (UsesKind.ACTION, UsesKind.REUSABLE_WORKFLOW)
        if remote:
            check(Field.ACTION, self.action)
            check(Field.GIT_REF, self.ref)
            if self.raw != f"{self.action}@{self.ref}":
                raise ValueError("a reference's halves are its raw value split at '@'")
        elif self.action is not None or self.ref is not None:
            raise ValueError("a local or Docker reference has no action or ref")
        # A local reference may be either; the others belong to one place only. A Docker
        # reference with neither job nor step is a Docker Action's own ``runs.image``.
        if self.step is not None:
            misplaced: tuple[UsesKind, ...] = (UsesKind.REUSABLE_WORKFLOW,)
        elif self.job is not None:
            misplaced = (UsesKind.ACTION, UsesKind.DOCKER)
        else:
            misplaced = (UsesKind.ACTION,)
        if self.kind in misplaced:
            raise ValueError("a step's reference names its step; a job's own reference does not")

    @property
    def image(self) -> str | None:
        """A Docker reference's image, ``docker://`` dropped; None for any other kind. Not yet
        grammar-checked: the finding that names it checks it (contracts §6, ``docker-image``)."""
        return self.raw.removeprefix(DOCKER_PREFIX) if self.kind is UsesKind.DOCKER else None

    @classmethod
    def read(cls, raw: str, *, file: str, line: int, job: str | None, step: int | None) -> UsesReference:
        """Classify ``raw`` as found at a step (``step`` given) or as a job's own ``uses``."""
        if raw.startswith("./"):
            return cls(raw, UsesKind.LOCAL, file, line, job, step)
        if step is not None and raw.startswith(DOCKER_PREFIX):
            return cls(raw, UsesKind.DOCKER, file, line, job, step)
        action, sep, ref = raw.rpartition("@")
        if not sep:
            raise MalformedValueError(Field.ACTION_STEP, raw, site="models.malformed-action-step")
        kind = UsesKind.ACTION if step is not None else UsesKind.REUSABLE_WORKFLOW
        return cls(raw, kind, file, line, job, step, check(Field.ACTION, action), check(Field.GIT_REF, ref))


@dataclass(frozen=True)
class Step:
    index: int  # 0-based position in ``steps``
    line: int
    uses: UsesReference | None


@dataclass(frozen=True)
class Job:
    """One workflow job: a reusable workflow call (``uses``), or ``steps``."""

    id: str
    line: int
    uses: UsesReference | None
    steps: tuple[Step, ...]


@dataclass(frozen=True)
class Workflow:
    """A workflow file. ``triggers`` are the event names under ``on``, in file order."""

    file: str
    triggers: tuple[str, ...]
    jobs: tuple[Job, ...]

    @property
    def is_reusable(self) -> bool:
        """Whether other workflows can call this one (``on: workflow_call``)."""
        return "workflow_call" in self.triggers

    @property
    def references(self) -> tuple[UsesReference, ...]:
        """Every ``uses:`` in file order: each job's own call, then its steps'."""
        refs: list[UsesReference] = []
        for job in self.jobs:
            refs.extend([job.uses] if job.uses is not None else [])
            refs.extend(step.uses for step in job.steps if step.uses is not None)
        return tuple(refs)


@dataclass(frozen=True)
class ActionMetadata:
    """An Action's ``action.yml``. ``using`` is ``runs.using`` as written; ``steps`` are
    ``runs.steps``; ``image`` is ``runs.image`` (a Docker Action's), None when there is none.

    A ``docker://`` image is a reference like a step's (kind ``docker``, no job or step); an
    image that names a Dockerfile in the Action's own repository is built from the commit the
    Action is read at, so it names nothing else and is not a reference.
    """

    file: str
    using: str
    steps: tuple[Step, ...]
    image: UsesReference | None = None

    def __post_init__(self) -> None:
        if self.image is not None and (self.image.kind is not UsesKind.DOCKER or self.image.step is not None):
            raise ValueError("an Action's image reference is a Docker reference with no step")

    @property
    def is_composite(self) -> bool:
        return self.using.lower() == "composite"

    @property
    def references(self) -> tuple[UsesReference, ...]:
        """Every reference in the metadata: each step's, then the Docker image's."""
        steps = tuple(step.uses for step in self.steps if step.uses is not None)
        return steps + ((self.image,) if self.image is not None else ())


def _refuse(file: str, line: int, detail: str, *, site: str) -> UnsupportedYamlError:
    record_site(site)
    return UnsupportedYamlError(file, line, _STRUCTURE, detail, site=site, recorded=True)


def _root(node: Node | None, file: str) -> MappingNode:
    if node is None:
        raise _refuse(file, 1, "the file is empty", site="models.file-empty")
    if not isinstance(node, MappingNode):
        raise _refuse(file, node.line, "the file is not a mapping", site="models.file-not-mapping")
    return node


def _mapping(node: Node, file: str, what: str) -> MappingNode:
    if not isinstance(node, MappingNode):
        raise _refuse(file, node.line, f"{what} is not a mapping", site="models.value-not-mapping")
    return node


def _value(node: Node, file: str, what: str) -> str:
    """A single, non-empty value (quoted or not; a text block's value is kept with its line breaks)."""
    if not isinstance(node, ScalarNode) or not node.value:
        raise _refuse(file, node.line, f"{what} is not a single value", site="models.not-single-value")
    return node.value


def _steps(node: Node, file: str, job: str | None) -> tuple[Step, ...]:
    if not isinstance(node, SequenceNode):
        raise _refuse(file, node.line, "'steps' is not a list", site="models.steps-not-list")
    steps: list[Step] = []
    for index, item in enumerate(node.items):
        step = _mapping(item, file, f"step {index + 1}")
        entry = step.get("uses")
        uses = None
        if entry is not None:
            raw = _value(entry.value, file, "a step's 'uses'")
            uses = UsesReference.read(raw, file=file, line=entry.line, job=job, step=index)
        steps.append(Step(index, step.line, uses))
    return tuple(steps)


def _triggers(node: Node, file: str) -> tuple[str, ...]:
    if isinstance(node, ScalarNode):
        return (_value(node, file, "'on'"),)
    if isinstance(node, SequenceNode):
        return tuple(_value(item, file, "an 'on' event") for item in node.items)
    return tuple(e.key for e in node.entries)


def workflow_from(root: Node | None, file: str) -> Workflow:
    """The workflow read from ``root``, the reader's result for ``file``."""
    top = _root(root, file)
    on = top.get("on")
    jobs_entry = top.get("jobs")
    if jobs_entry is None:
        raise _refuse(file, top.line, "a workflow has no 'jobs'", site="models.workflow-no-jobs")
    jobs: list[Job] = []
    for entry in _mapping(jobs_entry.value, file, "'jobs'").entries:
        body = _mapping(entry.value, file, f"job {entry.key!r}")
        uses_entry = body.get("uses")
        steps_entry = body.get("steps")
        uses = None
        if uses_entry is not None:
            raw = _value(uses_entry.value, file, f"job {entry.key!r}'s 'uses'")
            uses = UsesReference.read(raw, file=file, line=uses_entry.line, job=entry.key, step=None)
        steps = _steps(steps_entry.value, file, entry.key) if steps_entry is not None else ()
        jobs.append(Job(entry.key, entry.line, uses, steps))
    triggers = _triggers(on.value, file) if on is not None else ()
    return Workflow(file, triggers, tuple(jobs))


def action_from(root: Node | None, file: str) -> ActionMetadata:
    """The Action metadata read from ``root``, the reader's result for ``file``."""
    top = _root(root, file)
    runs_entry = top.get("runs")
    if runs_entry is None:
        raise _refuse(file, top.line, "an Action's metadata has no 'runs'", site="models.actions-metadata-no-runs")
    runs = _mapping(runs_entry.value, file, "'runs'")
    using_entry = runs.get("using")
    if using_entry is None:
        raise _refuse(file, runs.line, "'runs' has no 'using'", site="models.runs-no-using")
    using = _value(using_entry.value, file, "'runs.using'")
    # Steps are read wherever they are written, whatever ``using`` says, so a spelling the
    # runner accepts and this model does not expect ("Composite") cannot hide a reference.
    steps_entry = runs.get("steps")
    if steps_entry is None and using.lower() == "composite":
        raise _refuse(file, runs.line, "a composite Action has no 'steps'", site="models.composite-action-no-steps")
    steps = _steps(steps_entry.value, file, None) if steps_entry is not None else ()
    # Like steps, the image is read wherever it is written, whatever ``using`` says. Only a
    # ``docker://`` value names an image elsewhere; anything else (a Dockerfile, or a value the
    # runner refuses) names nothing to check and is read as before, so ``pin`` is unchanged.
    # The prefix in another letter case (``Docker://``) refuses the file: GitHub's documentation
    # does not say whether the runner reads it as an image, and it is never dropped (#143).
    image_entry = runs.get("image")
    image = None
    if image_entry is not None and isinstance(image_entry.value, ScalarNode):
        raw = image_entry.value.value
        if raw.startswith(DOCKER_PREFIX):
            image = UsesReference(raw, UsesKind.DOCKER, file, image_entry.line, None, None)
        elif raw[: len(DOCKER_PREFIX)].casefold() == DOCKER_PREFIX:
            raise _refuse(
                file,
                image_entry.line,
                "'runs.image' starts with docker:// in another letter case, which the runner may not read as an image",
                site="models.image-prefix-in-another-case",
            )
    return ActionMetadata(file, using, steps, image)


def load_workflow(path: str) -> Workflow:
    """Read the workflow file at ``path`` (read-only)."""
    return workflow_from(yaml_subset.load(path), path)


def load_action(path: str) -> ActionMetadata:
    """Read the Action metadata file (``action.yml``) at ``path`` (read-only)."""
    return action_from(yaml_subset.load(path), path)
