from sentrix.core.trace_stream import StreamEvent, TraceStream
from sentrix.models.events import ActionVerdict, TraceEvent


class TestTraceStream:
    def test_publish_and_replay(self):
        stream = TraceStream(max_buffer=100)
        event = TraceEvent(
            id="evt_1",
            session_id="s1",
            agent_id="agent_1",
            content="test_action",
            verdict=ActionVerdict.ALLOWED,
        )
        stream.publish(StreamEvent(event=event, session_id="s1", agent_id="agent_1"))
        stream.publish(StreamEvent(event=event, session_id="s2", agent_id="agent_2"))

        assert len(stream.replay("s1")) == 1
        assert len(stream.replay("s2")) == 1
        assert len(stream.replay("s3")) == 0

    def test_subscriber_notified(self):
        stream = TraceStream()
        received: list[StreamEvent] = []

        def cb(se: StreamEvent) -> None:
            received.append(se)

        stream.subscribe("test_sub", cb)
        event = TraceEvent(
            id="evt_1",
            session_id="s1",
            agent_id="agent_1",
            content="test",
            verdict=ActionVerdict.ALLOWED,
        )
        stream.publish(StreamEvent(event=event, session_id="s1", agent_id="agent_1"))
        assert len(received) == 1
        assert received[0].event.id == "evt_1"

    def test_unsubscribe(self):
        stream = TraceStream()
        received: list[StreamEvent] = []

        def cb(se: StreamEvent) -> None:
            received.append(se)

        stream.subscribe("test", cb)
        stream.unsubscribe("test", cb)
        stream.publish(StreamEvent(
            event=TraceEvent(
                id="e1", session_id="s1", agent_id="a1",
                content="t", verdict=ActionVerdict.ALLOWED,
            ),
            session_id="s1", agent_id="a1",
        ))
        assert len(received) == 0

    def test_clear_session(self):
        stream = TraceStream()
        for i in range(5):
            event = TraceEvent(
                id=f"e{i}", session_id="s1", agent_id="a1",
                content="t", verdict=ActionVerdict.ALLOWED,
            )
            stream.publish(StreamEvent(event=event, session_id="s1", agent_id="a1"))
        for i in range(3):
            event = TraceEvent(
                id=f"e{i}", session_id="s2", agent_id="a2",
                content="t", verdict=ActionVerdict.ALLOWED,
            )
            stream.publish(StreamEvent(event=event, session_id="s2", agent_id="a2"))

        assert stream.clear_session("s1") == 5
        assert stream.buffer_size == 3

    def test_max_buffer(self):
        stream = TraceStream(max_buffer=5)
        for i in range(10):
            event = TraceEvent(
                id=f"e{i}", session_id="s1", agent_id="a1",
                content="t", verdict=ActionVerdict.ALLOWED,
            )
            stream.publish(StreamEvent(event=event, session_id="s1", agent_id="a1"))
        assert stream.buffer_size == 5
        assert stream.replay("s1")[0].event.id == "e5"

    def test_subscriber_exception_does_not_crash(self):
        stream = TraceStream()

        def failing_cb(se: StreamEvent) -> None:
            raise ValueError("oops")

        stream.subscribe("failing", failing_cb)
        event = TraceEvent(
            id="e1", session_id="s1", agent_id="a1",
            content="t", verdict=ActionVerdict.ALLOWED,
        )
        stream.publish(StreamEvent(event=event, session_id="s1", agent_id="a1"))
