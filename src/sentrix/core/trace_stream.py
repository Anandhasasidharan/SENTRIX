from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from sentrix.models.events import TraceEvent


@dataclass
class StreamEvent:
    event: TraceEvent
    session_id: str
    agent_id: str
    metadata: dict[str, Any] = field(default_factory=dict)


class TraceStream:
    def __init__(self, max_buffer: int = 10000):
        self._subscribers: dict[str, list[Callable[[StreamEvent], None]]] = {}
        self._buffer: list[StreamEvent] = []
        self._max_buffer = max_buffer
        self._lock = threading.Lock()

    def subscribe(self, subscriber_id: str, callback: Callable[[StreamEvent], None]) -> None:
        with self._lock:
            self._subscribers.setdefault(subscriber_id, []).append(callback)

    def unsubscribe(self, subscriber_id: str, callback: Callable[[StreamEvent], None] | None = None) -> None:
        with self._lock:
            if callback is None:
                self._subscribers.pop(subscriber_id, None)
            elif subscriber_id in self._subscribers:
                self._subscribers[subscriber_id] = [
                    c for c in self._subscribers[subscriber_id] if c is not callback
                ]

    def publish(self, event: StreamEvent) -> None:
        with self._lock:
            self._buffer.append(event)
            if len(self._buffer) > self._max_buffer:
                self._buffer = self._buffer[-self._max_buffer:]

            for subscriber_id, callbacks in self._subscribers.items():
                for callback in callbacks:
                    try:
                        callback(event)
                    except Exception:
                        import logging
                        logging.getLogger(__name__).exception(
                            "Subscriber %s failed to handle event", subscriber_id
                        )

    def replay(self, session_id: str, max_events: int | None = None) -> list[StreamEvent]:
        with self._lock:
            matching = [s for s in self._buffer if s.session_id == session_id]
            if max_events is not None:
                matching = matching[-max_events:]
            return list(matching)

    def clear_session(self, session_id: str) -> int:
        with self._lock:
            before = len(self._buffer)
            self._buffer = [s for s in self._buffer if s.session_id != session_id]
            return before - len(self._buffer)

    @property
    def buffer_size(self) -> int:
        with self._lock:
            return len(self._buffer)


class StreamCollector:
    def __init__(self, stream: TraceStream):
        self._stream = stream

    def emit(
        self,
        event: TraceEvent,
        session_id: str,
        agent_id: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        stream_event = StreamEvent(
            event=event,
            session_id=session_id,
            agent_id=agent_id,
            metadata=metadata or {},
        )
        self._stream.publish(stream_event)
