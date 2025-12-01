"""
AuthModeler State Machine Base

Abstract base class for protocol state machines with:
- Invariant checking at each transition
- Complete transition history for verification
- TLA+ trace export for conformance testing

SPEC: specs/tla/Kerberos.tla, specs/tla/NTLM.tla

Design Principles:
1. Pure transition functions (no side effects in handlers)
2. All state changes through explicit transitions
3. Invariant checking before committing state changes
4. Complete transition history for replay/verification
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from enum import Enum
from typing import (
    Any,
    Callable,
    Dict,
    Generic,
    List,
    Optional,
    Tuple,
    TypeVar,
    Union,
)
import json
import structlog

import attrs
from returns.result import Failure, Result, Success

from authmodeler.core.exceptions import InvariantViolation, StateError

logger = structlog.get_logger()


# Type variables for generic state machine
S = TypeVar("S", bound=Enum)  # State type
E = TypeVar("E")  # Event type
C = TypeVar("C")  # Context type


@attrs.define(frozen=True, slots=True)
class Transition(Generic[S, E]):
    """
    Immutable record of a state transition.

    Used for audit logging and TLA+ trace validation.

    SPEC: specs/tla/Kerberos.tla - history variable
    """

    from_state: S
    event_type: str
    to_state: S
    timestamp: datetime
    context_snapshot: Dict[str, Any] = attrs.Factory(dict)
    event_data: Dict[str, Any] = attrs.Factory(dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "from_state": self.from_state.name,
            "event_type": self.event_type,
            "to_state": self.to_state.name,
            "timestamp": self.timestamp.isoformat(),
            "context_snapshot": self.context_snapshot,
            "event_data": self.event_data,
        }


# Type alias for invariant functions
InvariantFn = Callable[[S, Any], bool]

# Type alias for transition table entry
TransitionEntry = Tuple[S, Callable[[Any, Any], Any]]


@attrs.define
class StateMachineBase(ABC, Generic[S, E, C]):
    """
    Base state machine with formal verification hooks.

    SPEC: specs/tla/Kerberos.tla - Spec definition

    Design principles:
    1. Pure transition function (no side effects)
    2. All state changes through transitions
    3. Invariant checking at each step
    4. Complete transition history for replay/verification

    Usage:
        class MyStateMachine(StateMachineBase[MyState, MyEvent, MyContext]):
            def initial_state(self) -> MyState:
                return MyState.INITIAL

            def transition_table(self) -> Dict[Tuple[MyState, type], TransitionEntry]:
                return {
                    (MyState.INITIAL, StartEvent): (
                        MyState.STARTED,
                        self._handle_start
                    ),
                }

            @staticmethod
            def _handle_start(event: StartEvent, ctx: MyContext) -> MyContext:
                return attrs.evolve(ctx, started=True)
    """

    _state: S = attrs.field(alias="_state")
    _context: C = attrs.field(alias="_context")
    _history: List[Transition[S, E]] = attrs.field(factory=list, alias="_history")
    _invariants: List[Tuple[str, InvariantFn]] = attrs.field(factory=list, alias="_invariants")
    _logger: Any = attrs.field(factory=lambda: structlog.get_logger(), alias="_logger")

    @abstractmethod
    def initial_state(self) -> S:
        """Return the initial state for this state machine."""
        ...

    @abstractmethod
    def transition_table(
        self,
    ) -> Dict[Tuple[S, type], TransitionEntry]:
        """
        Return the transition table.

        Maps (current_state, event_type) to (next_state, context_updater).

        The context_updater is a pure function that computes new context
        from the event and current context.
        """
        ...

    @property
    def state(self) -> S:
        """Current state (read-only)."""
        return self._state

    @property
    def context(self) -> C:
        """Current context (read-only)."""
        return self._context

    def process_event(self, event: E) -> Result[S, str]:
        """
        Process an event and transition to the next state.

        SPEC: specs/tla/Kerberos.tla - Next state relation

        Returns:
            Success(new_state) if transition succeeded
            Failure(error_message) if transition failed

        Raises:
            InvariantViolation: If any invariant fails after transition
        """
        event_type = type(event)
        key = (self._state, event_type)

        # Check if transition is defined
        table = self.transition_table()
        if key not in table:
            error_msg = f"No transition for state {self._state.name} with event {event_type.__name__}"
            self._logger.warning(
                "invalid_transition",
                current_state=self._state.name,
                event_type=event_type.__name__,
            )
            return Failure(error_msg)

        next_state, context_updater = table[key]

        # Compute new context using pure function
        try:
            new_context = context_updater(event, self._context)
        except Exception as e:
            error_msg = f"Context update failed: {e}"
            self._logger.error(
                "context_update_failed",
                error=str(e),
                current_state=self._state.name,
                event_type=event_type.__name__,
            )
            return Failure(error_msg)

        # Check invariants BEFORE committing transition
        for name, invariant in self._invariants:
            try:
                if not invariant(next_state, new_context):
                    error_msg = f"Invariant '{name}' violated"
                    self._logger.error(
                        "invariant_violated",
                        invariant=name,
                        from_state=self._state.name,
                        to_state=next_state.name,
                    )
                    raise InvariantViolation(error_msg)
            except InvariantViolation:
                raise
            except Exception as e:
                error_msg = f"Invariant check '{name}' failed: {e}"
                self._logger.error("invariant_check_failed", invariant=name, error=str(e))
                return Failure(error_msg)

        # Record transition
        transition = Transition(
            from_state=self._state,
            event_type=event_type.__name__,
            to_state=next_state,
            timestamp=datetime.now(timezone.utc),
            context_snapshot=self._snapshot_context(new_context),
            event_data=self._snapshot_event(event),
        )
        self._history.append(transition)

        # Log transition
        self._logger.info(
            "state_transition",
            from_state=self._state.name,
            to_state=next_state.name,
            event_type=event_type.__name__,
        )

        # Commit state change
        self._state = next_state
        self._context = new_context

        return Success(next_state)

    def add_invariant(self, name: str, invariant: InvariantFn) -> None:
        """
        Register an invariant to be checked at each transition.

        SPEC: specs/alloy/kerberos/properties.als - assertions

        Args:
            name: Human-readable name for error messages
            invariant: Function (state, context) -> bool
        """
        self._invariants.append((name, invariant))

    def get_trace(self) -> List[Transition[S, E]]:
        """
        Return complete transition history.

        Used for:
        - Audit logging
        - TLA+ trace validation
        - Debugging

        Returns:
            Copy of transition history
        """
        return list(self._history)

    def export_for_tla(self) -> Dict[str, Any]:
        """
        Export trace in format suitable for TLA+ trace validation.

        SPEC: specs/tla/KerberosProps.tla - trace validation

        Returns:
            Dictionary with states, events, and timestamps
        """
        states = [t.from_state.name for t in self._history]
        if self._history:
            states.append(self._history[-1].to_state.name)
        else:
            states.append(self._state.name)

        return {
            "states": states,
            "events": [t.event_type for t in self._history],
            "timestamps": [t.timestamp.isoformat() for t in self._history],
        }

    def export_trace_json(self) -> str:
        """Export trace as JSON string."""
        return json.dumps(
            {
                "initial_state": self.initial_state().name,
                "final_state": self._state.name,
                "transitions": [t.to_dict() for t in self._history],
                "tla_format": self.export_for_tla(),
            },
            indent=2,
        )

    def _snapshot_context(self, context: C) -> Dict[str, Any]:
        """Create a serializable snapshot of the context."""
        if attrs.has(type(context)):
            return attrs.asdict(
                context,
                filter=lambda attr, value: not attr.name.startswith("_"),
                value_serializer=self._serialize_value,
            )
        return {}

    def _snapshot_event(self, event: E) -> Dict[str, Any]:
        """Create a serializable snapshot of the event."""
        if attrs.has(type(event)):
            return attrs.asdict(
                event,
                filter=lambda attr, value: not attr.name.startswith("_"),
                value_serializer=self._serialize_value,
            )
        return {"type": type(event).__name__}

    @staticmethod
    def _serialize_value(
        inst: type, field: attrs.Attribute, value: Any  # noqa: ARG004
    ) -> Any:
        """Serialize values for JSON export."""
        if isinstance(value, bytes):
            return f"<bytes:{len(value)}>"
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, Enum):
            return value.name
        if attrs.has(type(value)):
            return f"<{type(value).__name__}>"
        return value

    def reset(self) -> None:
        """
        Reset state machine to initial state.

        Clears context and history. Useful for testing.
        """
        self._state = self.initial_state()
        self._history = []
        # Note: context is not reset - subclass should handle if needed


# =============================================================================
# VERIFICATION HELPERS
# =============================================================================


def verify_trace_against_spec(
    trace: List[Transition],
    allowed_transitions: Dict[Tuple[str, str], str],
) -> List[str]:
    """
    Verify a trace against an allowed transitions specification.

    Args:
        trace: List of transitions to verify
        allowed_transitions: Dict mapping (from_state, event) to to_state

    Returns:
        List of error messages (empty if valid)
    """
    errors = []

    for i, t in enumerate(trace):
        key = (t.from_state.name, t.event_type)
        if key not in allowed_transitions:
            errors.append(
                f"Transition {i}: Invalid transition {t.from_state.name} "
                f"--[{t.event_type}]--> {t.to_state.name}"
            )
        elif allowed_transitions[key] != t.to_state.name:
            errors.append(
                f"Transition {i}: Expected {t.from_state.name} "
                f"--[{t.event_type}]--> {allowed_transitions[key]}, "
                f"got {t.to_state.name}"
            )

    return errors


def check_invariant_over_trace(
    trace: List[Transition],
    invariant: Callable[[str, Dict[str, Any]], bool],
    invariant_name: str,
) -> List[str]:
    """
    Check an invariant holds over all states in a trace.

    Args:
        trace: List of transitions
        invariant: Function (state_name, context_snapshot) -> bool
        invariant_name: Name for error messages

    Returns:
        List of error messages (empty if invariant holds)
    """
    errors = []

    for i, t in enumerate(trace):
        if not invariant(t.to_state.name, t.context_snapshot):
            errors.append(
                f"Invariant '{invariant_name}' violated at transition {i}: "
                f"state={t.to_state.name}"
            )

    return errors
