import pytest

from sentrix.models.events import ActionVerdict, DetectorLayer, TraceEvent
from sentrix.replay.timeline import AttackDAGBuilder, Timeline


class TestTimeline:
    @pytest.fixture
    def timeline(self):
        return Timeline()

    def _make_event(self, agent_id="agent_a", session="session_1", **kw):
        return TraceEvent(
            agent_id=agent_id,
            session_id=session,
            **kw,
        )

    def test_add_and_retrieve_event(self, timeline):
        event = self._make_event(content="hello")
        timeline.add_event(event)
        events = timeline.get_events()
        assert len(events) == 1
        assert events[0].content == "hello"

    def test_filter_by_session(self, timeline):
        timeline.add_event(self._make_event(session="s1", content="a"))
        timeline.add_event(self._make_event(session="s2", content="b"))
        assert len(timeline.get_events(session_id="s1")) == 1

    def test_filter_by_agent(self, timeline):
        timeline.add_event(self._make_event(agent_id="alice"))
        timeline.add_event(self._make_event(agent_id="bob"))
        assert len(timeline.get_events(agent_id="alice")) == 1

    def test_event_count(self, timeline):
        timeline.add_event(self._make_event())
        timeline.add_event(self._make_event())
        assert timeline.get_event_count() == 2

    def test_render_text_timeline(self, timeline):
        event = self._make_event(content="test query")
        timeline.add_event(event)
        text = timeline.render_text_timeline("session_1")
        assert "test query" in text


class TestAttackDAGBuilder:
    @pytest.fixture
    def builder(self):
        return AttackDAGBuilder()

    def test_add_event_creates_node(self, builder):
        event = TraceEvent(
            agent_id="agent_a",
            session_id="s1",
            content="test",
            verdict=ActionVerdict.BLOCKED,
            blocked_by=DetectorLayer.REFERENCE_MONITOR,
        )
        node = builder.add_event(event)
        assert node.event_id == event.id
        assert node.verdict == ActionVerdict.BLOCKED
        assert node.blocked_by == DetectorLayer.REFERENCE_MONITOR

    def test_build_dag_with_parent_child(self, builder):
        timeline = Timeline()

        parent = TraceEvent(
            agent_id="agent_a", session_id="s1", content="parent"
        )
        timeline.add_event(parent)
        builder.add_event(parent)

        child = TraceEvent(
            agent_id="agent_b",
            session_id="s1",
            content="child",
            parent_event_id=parent.id,
        )
        timeline.add_event(child)
        builder.add_event(child)

        dag = builder.build_dag("s1", timeline)
        assert dag is not None
        assert len(dag.children) == 1

    def test_summary_returns_stats(self, builder):
        timeline = Timeline()
        timeline.add_event(
            TraceEvent(
                agent_id="a",
                session_id="s1",
                content="ok",
                verdict=ActionVerdict.ALLOWED,
            )
        )
        timeline.add_event(
            TraceEvent(
                agent_id="a",
                session_id="s1",
                content="bad",
                verdict=ActionVerdict.BLOCKED,
                blocked_by=DetectorLayer.REFERENCE_MONITOR,
            )
        )
        summary = builder.summary("s1", timeline)
        assert summary["total_events"] == 2
        assert summary["blocked"] == 1
        assert summary["allowed"] == 1
