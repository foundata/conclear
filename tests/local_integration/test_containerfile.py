from pathlib import Path

import pytest

from conclear.containerfile import load_containerfile
from conclear.errors import InvalidInvocationError
from conclear.path_safety import contained_path
from conclear.runtime import ApplicationRuntime
from conclear.services.adoption_observation import observe_containerfile
from conclear.tools import ToolName
from conclear.values import Platform
from tests.local_integration.fixtures import compile_fixture, manifest_run_id

pytestmark = pytest.mark.local_integration


def test_complex_lexical_facts_match_real_buildah_config(tmp_path: Path) -> None:
    run_id = manifest_run_id()
    root = contained_path(tmp_path, run_id, must_exist=False)
    runtime = ApplicationRuntime.create(root / "environment", names=(ToolName.BUILDAH,))
    context = compile_fixture(runtime, root=root, architecture="amd64")
    path = context / "Containerfile"
    path.write_text(
        "# escape=\\\n"
        "FROM scratch AS build\n"
        "COPY conclear-fixture /app\n"
        'COPY ["payload", "/payload"]\n'
        "FROM scratch AS runtime\n"
        "COPY --chown=1000:1000 \\\n"
        "    # Comment within a continued builder flag prefix.\n"
        '    --from="build" ["/app", "/app"]\n'
        'RUN --mount="type=bind,from=build,source=/payload,target=/a b" '
        '["/app", "one-shot", "--mount=from=not-an-image"]\n'
        'LABEL joined="hel\\\n'
        'lo"\n'
        'LABEL spaced="two words"\n'
        "USER 1000:1000\n"
        "STOPSIGNAL SIGTERM\n"
        'ENTRYPOINT ["/app"]\n'
        'CMD ["one-shot"]\n',
        encoding="utf-8",
    )
    (context / "payload").write_text("mount fixture\n", encoding="utf-8")
    source = load_containerfile(path)
    observation = observe_containerfile(context, path, image_id="fixture")
    storage, runroot = root / "buildah-root", root / "buildah-runroot"
    try:
        result = runtime.buildah().build(
            root=storage,
            runroot=runroot,
            containerfile=path,
            context=context,
            platform=Platform.parse("linux/amd64"),
            image_name=f"localhost/llmtest-{run_id.lower()}-syntax:fixture",
            layout_path=root / "layout",
            layout_reference="fixture",
            source_epoch=946684800,
            build_arguments={},
            auth_file=None,
        )
        config = result.graph.manifests[0].config_data["config"]
        assert isinstance(config, dict)
        assert (
            config["Labels"]
            == dict(observation.labels)
            == {"joined": "hello", "spaced": "two words"}
        )
        assert config["User"] == observation.user.raw == "1000:1000"
        assert config["StopSignal"] == observation.stop_signal == "SIGTERM"
        assert config["Entrypoint"] == list(observation.entrypoint.command) == ["/app"]
        assert (
            config["Cmd"]
            == list(source.instructions[-1].exec_command or ())
            == ["one-shot"]
        )
        assert source.external_inputs == ()
        assert observation.findings == ()
    finally:
        runtime.buildah().remove_storage(root=storage, runroot=runroot)


@pytest.mark.parametrize(
    "content",
    [
        "FROM scratch\nCOPY <<EOF /payload\nfixture\nEOF\n",
        '# escape=`\nFROM scratch\nLABEL joined="hel`\nlo"\n',
    ],
    ids=("heredoc", "backtick-escape"),
)
def test_valid_builder_extensions_are_explicitly_outside_the_subset(
    tmp_path: Path, content: str
) -> None:
    run_id = manifest_run_id()
    root = contained_path(tmp_path, run_id, must_exist=False)
    runtime = ApplicationRuntime.create(root / "environment", names=(ToolName.BUILDAH,))
    context = root / "context"
    context.mkdir()
    path = context / "Containerfile"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(InvalidInvocationError, match="supported Containerfile syntax"):
        load_containerfile(path)
    storage, runroot = root / "buildah-root", root / "buildah-runroot"
    try:
        result = runtime.buildah().build(
            root=storage,
            runroot=runroot,
            containerfile=path,
            context=context,
            platform=Platform.parse("linux/amd64"),
            image_name=f"localhost/llmtest-{run_id.lower()}-extension:fixture",
            layout_path=root / "layout",
            layout_reference="fixture",
            source_epoch=946684800,
            build_arguments={},
            auth_file=None,
        )
        assert len(result.graph.manifests) == 1
    finally:
        runtime.buildah().remove_storage(root=storage, runroot=runroot)
