from __future__ import annotations

from d810.manager.profiling import CProfileWrapper, ProfilingController


def test_profiling_controller_dumps_cprofile_segments_and_final_profile(tmp_path):
    controller = ProfilingController(
        tmp_path,
        profiler=None,
        cprofiler=CProfileWrapper(),
    )

    controller.enable()

    assert controller.is_running
    segment_path = controller.dump_segment("MMAT_GLBOPT1")
    assert segment_path == tmp_path / "d810_cprofile_MMAT_GLBOPT1.prof"
    assert segment_path.exists()
    assert controller.is_running

    final_path = controller.stop()

    assert final_path == tmp_path / "d810_cprofile.prof"
    assert final_path.exists()
    assert not controller.is_running


def test_profiling_controller_noops_when_no_profiler_is_available(tmp_path):
    controller = ProfilingController(
        tmp_path,
        profiler=None,
        cprofiler=None,
    )

    controller.enable()

    assert not controller.is_running
    assert controller.dump_segment("MMAT_GLBOPT1") is None
    assert controller.stop() is None


def test_profiling_controller_timer_can_stop_without_reporting(tmp_path):
    controller = ProfilingController(
        tmp_path,
        profiler=None,
        cprofiler=None,
    )

    controller.start_timer()
    controller.stop_timer(report=False)

    assert controller._start_ts == 0.0
