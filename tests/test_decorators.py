"""Tests for decorators and Instruments enum."""

import pytest


class TestDecoratorWrappers:
    """Tests that decorator wrappers work correctly."""

    def test_task_decorator_is_callable(self) -> None:
        """Test that @task decorator is available and callable."""
        from fortifyroot import task

        assert callable(task)

    def test_workflow_decorator_is_callable(self) -> None:
        """Test that @workflow decorator is available and callable."""
        from fortifyroot import workflow

        assert callable(workflow)

    def test_agent_decorator_is_callable(self) -> None:
        """Test that @agent decorator is available and callable."""
        from fortifyroot import agent

        assert callable(agent)

    def test_tool_decorator_is_callable(self) -> None:
        """Test that @tool decorator is available and callable."""
        from fortifyroot import tool

        assert callable(tool)

    def test_decorators_are_fr_functions_not_tl(self) -> None:
        """Test that decorators are FR's own functions, not TL re-exports."""
        from fortifyroot import task, workflow, agent, tool
        from fortifyroot._vendor.traceloop.sdk.decorators import (
            task as tl_task,
            workflow as tl_workflow,
            agent as tl_agent,
            tool as tl_tool,
        )

        # FR decorators should NOT be the same object as TL decorators
        # They are wrapper functions that delegate to TL
        assert task is not tl_task
        assert workflow is not tl_workflow
        assert agent is not tl_agent
        assert tool is not tl_tool

    def test_decorators_module_path(self) -> None:
        """Test that decorators are defined in fortifyroot module."""
        from fortifyroot import task, workflow, agent, tool

        assert task.__module__ == "fortifyroot.decorators"
        assert workflow.__module__ == "fortifyroot.decorators"
        assert agent.__module__ == "fortifyroot.decorators"
        assert tool.__module__ == "fortifyroot.decorators"

    def test_decorators_have_docstrings(self) -> None:
        """Test that decorators have FR docstrings."""
        from fortifyroot import task, workflow, agent, tool

        assert task.__doc__ is not None
        assert "task" in task.__doc__.lower()

        assert workflow.__doc__ is not None
        assert "workflow" in workflow.__doc__.lower()

        assert agent.__doc__ is not None
        assert "agent" in agent.__doc__.lower()

        assert tool.__doc__ is not None
        assert "tool" in tool.__doc__.lower()

    def test_task_decorator_can_decorate_function(self) -> None:
        """Test that @task can be applied to functions."""
        from fortifyroot import task

        @task(name="test_task")
        def my_task() -> str:
            return "task_result"

        assert callable(my_task)

    def test_workflow_decorator_can_decorate_function(self) -> None:
        """Test that @workflow can be applied to functions."""
        from fortifyroot import workflow

        @workflow(name="test_workflow")
        def my_workflow() -> str:
            return "workflow_result"

        assert callable(my_workflow)

    def test_agent_decorator_can_decorate_function(self) -> None:
        """Test that @agent can be applied to functions."""
        from fortifyroot import agent

        @agent(name="test_agent")
        def my_agent() -> str:
            return "agent_result"

        assert callable(my_agent)

    def test_tool_decorator_can_decorate_function(self) -> None:
        """Test that @tool can be applied to functions."""
        from fortifyroot import tool

        @tool(name="test_tool")
        def my_tool() -> str:
            return "tool_result"

        assert callable(my_tool)

    def test_decorator_accepts_all_parameters(self) -> None:
        """Test that decorators accept name, version, and method_name params."""
        from fortifyroot import task, workflow

        # Should not raise any errors
        @task(name="my_task", version=1)
        def task_func() -> str:
            return "result"

        @workflow(name="my_workflow", version=2)
        def workflow_func() -> str:
            return "result"

        assert callable(task_func)
        assert callable(workflow_func)


class TestInstrumentsEnum:
    """Tests that Instruments enum works correctly."""

    def test_instruments_is_fr_enum_not_tl(self) -> None:
        """Test that Instruments is FR's own enum, not TL re-export."""
        from fortifyroot import Instruments
        from fortifyroot._vendor.traceloop.sdk.instruments import Instruments as TLInstruments

        # FR Instruments should NOT be the same class as TL Instruments
        assert Instruments is not TLInstruments

    def test_instruments_module_path(self) -> None:
        """Test that Instruments is defined in fortifyroot module."""
        from fortifyroot import Instruments

        assert Instruments.__module__ == "fortifyroot.instruments"

    def test_instruments_has_expected_llm_providers(self) -> None:
        """Test that Instruments enum has LLM provider members."""
        from fortifyroot import Instruments

        # LLM Providers
        assert hasattr(Instruments, "OPENAI")
        assert hasattr(Instruments, "ANTHROPIC")
        assert hasattr(Instruments, "COHERE")
        assert hasattr(Instruments, "GOOGLE_GENERATIVEAI")
        assert hasattr(Instruments, "MISTRAL")
        assert hasattr(Instruments, "GROQ")
        assert hasattr(Instruments, "OLLAMA")
        assert hasattr(Instruments, "BEDROCK")
        assert hasattr(Instruments, "VERTEXAI")

    def test_instruments_has_expected_frameworks(self) -> None:
        """Test that Instruments enum has framework members."""
        from fortifyroot import Instruments

        # Frameworks
        assert hasattr(Instruments, "LANGCHAIN")
        assert hasattr(Instruments, "LLAMA_INDEX")
        assert hasattr(Instruments, "HAYSTACK")
        assert hasattr(Instruments, "CREWAI")

    def test_instruments_has_expected_vector_dbs(self) -> None:
        """Test that Instruments enum has vector database members."""
        from fortifyroot import Instruments

        # Vector DBs
        assert hasattr(Instruments, "PINECONE")
        assert hasattr(Instruments, "CHROMA")
        assert hasattr(Instruments, "MILVUS")
        assert hasattr(Instruments, "QDRANT")
        assert hasattr(Instruments, "WEAVIATE")

    def test_instruments_values_match_tl(self) -> None:
        """Test that FR Instruments values match TL Instruments values."""
        from fortifyroot import Instruments
        from fortifyroot._vendor.traceloop.sdk.instruments import Instruments as TLInstruments

        # Check that string values match for common instruments
        assert Instruments.OPENAI.value == TLInstruments.OPENAI.value
        assert Instruments.ANTHROPIC.value == TLInstruments.ANTHROPIC.value
        assert Instruments.LANGCHAIN.value == TLInstruments.LANGCHAIN.value
        assert Instruments.PINECONE.value == TLInstruments.PINECONE.value

    def test_instruments_can_be_used_in_set(self) -> None:
        """Test that Instruments can be used in a set (for init params)."""
        from fortifyroot import Instruments

        instrument_set = {Instruments.OPENAI, Instruments.LANGCHAIN}

        assert len(instrument_set) == 2
        assert Instruments.OPENAI in instrument_set
        assert Instruments.LANGCHAIN in instrument_set

    def test_instruments_has_docstring(self) -> None:
        """Test that Instruments enum has documentation."""
        from fortifyroot import Instruments

        assert Instruments.__doc__ is not None
        assert "LLM" in Instruments.__doc__ or "instrument" in Instruments.__doc__.lower()


class TestInstrumentsConversion:
    """Tests for FR to TL Instruments conversion."""

    def test_convert_none_returns_none(self) -> None:
        """Test that converting None returns None."""
        from fortifyroot.instruments import _convert_to_tl_instruments

        result = _convert_to_tl_instruments(None)
        assert result is None

    def test_convert_empty_set_returns_empty_set(self) -> None:
        """Test that converting empty set returns empty set."""
        from fortifyroot.instruments import _convert_to_tl_instruments

        result = _convert_to_tl_instruments(set())
        assert result == set()

    def test_convert_single_instrument(self) -> None:
        """Test converting a single instrument."""
        from fortifyroot import Instruments
        from fortifyroot.instruments import _convert_to_tl_instruments
        from fortifyroot._vendor.traceloop.sdk.instruments import Instruments as TLInstruments

        fr_set = {Instruments.OPENAI}
        tl_set = _convert_to_tl_instruments(fr_set)

        assert tl_set is not None
        assert len(tl_set) == 1
        assert TLInstruments.OPENAI in tl_set

    def test_convert_multiple_instruments(self) -> None:
        """Test converting multiple instruments."""
        from fortifyroot import Instruments
        from fortifyroot.instruments import _convert_to_tl_instruments
        from fortifyroot._vendor.traceloop.sdk.instruments import Instruments as TLInstruments

        fr_set = {Instruments.OPENAI, Instruments.LANGCHAIN, Instruments.PINECONE}
        tl_set = _convert_to_tl_instruments(fr_set)

        assert tl_set is not None
        assert len(tl_set) == 3
        assert TLInstruments.OPENAI in tl_set
        assert TLInstruments.LANGCHAIN in tl_set
        assert TLInstruments.PINECONE in tl_set
